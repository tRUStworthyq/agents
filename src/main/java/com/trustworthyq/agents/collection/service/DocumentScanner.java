package com.trustworthyq.agents.collection.service;

import com.trustworthyq.agents.collection.dto.DocumentEvidence;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.regex.Pattern;

public final class DocumentScanner {
    private static final int MAX_TEXT_BYTES = 1024 * 1024;
    private static final int MAX_DOCUMENT_BYTES = 8 * 1024 * 1024;
    private static final int MAX_REFERENCES = 2000;
    private static final int MAX_FINGERPRINTS = 128;
    private static final Pattern WORDS = Pattern.compile("[\\p{L}\\p{N}]{2,64}");
    private static final Pattern IDENTIFIERS = Pattern.compile(
            "(?U)\\b(договор|проект|заказ|contract|project|order|invoice)\\s*(?:№|#|:|no\\.?\\s*)\\s*"
                    + "([\\p{L}\\p{N}][\\p{L}\\p{N}._/-]{2,47})(?![\\p{L}\\p{N}])");
    private static final Set<String> TEXT_EXTENSIONS = Set.of("txt", "md", "csv", "tsv", "json", "xml", "html",
            "htm", "yaml", "yml", "log", "rst", "tex");
    private static final Pattern REFERENCES = Pattern.compile(
            "(?i)(?:\\]\\(<?([^<>\\r\\n)]{1,2048})>?\\)|(?:href|src)\\s*=\\s*[\"']([^\"'\\r\\n]{1,2048})[\"']"
                    + "|(?<![\\p{L}\\p{N}_.@/:-])((?:s3://|file:///)?[\\p{L}\\p{N}_.%~+/\\\\-]{1,2048}"
                    + "\\.(?:txt|md|csv|tsv|json|xml|html?|ya?ml|pdf|docx?|xlsx?|pptx?|odt|ods|zip))"
                    + "(?![\\p{L}\\p{N}_@/]))");

    private enum Format { TEXT, PDF, OFFICE, UNSUPPORTED }

    private final Format format;
    private final Map<UUID, String> terms;
    private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private boolean truncated;

    public DocumentScanner(String extension, String contentType, Map<UUID, String> terms) {
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        this.format = switch (extension.toLowerCase(Locale.ROOT)) {
            case "pdf" -> Format.PDF;
            case "docx", "xlsx", "pptx", "docm", "xlsm", "pptm" -> Format.OFFICE;
            default -> type.startsWith("application/pdf") ? Format.PDF
                    : type.contains("officedocument") ? Format.OFFICE
                    : TEXT_EXTENSIONS.contains(extension.toLowerCase(Locale.ROOT)) || type.startsWith("text/")
                    ? Format.TEXT : Format.UNSUPPORTED;
        };
        this.terms = terms;
    }

    void feed(byte[] buffer, int length) {
        if (format != Format.UNSUPPORTED) {
            int limit = format == Format.TEXT ? MAX_TEXT_BYTES : MAX_DOCUMENT_BYTES;
            int count = Math.min(length, limit - bytes.size());
            bytes.write(buffer, 0, count);
            truncated |= count < length;
        }
    }

    public DocumentEvidence finish(String eTag) {
        if (format == Format.UNSUPPORTED) return new DocumentEvidence(Set.of(), terms.keySet(), Set.of(), true, false, eTag, Set.of());
        var document = switch (format) {
            case PDF -> truncated ? new DocumentText("", Set.of(), false) : DocumentText.pdf(bytes.toByteArray());
            case OFFICE -> truncated ? new DocumentText("", Set.of(), false) : DocumentText.office(bytes.toByteArray());
            case TEXT -> plainText();
            case UNSUPPORTED -> throw new IllegalStateException("Unsupported document format");
        };
        String content = document.content();
        String folded = content.toLowerCase(Locale.ROOT);
        Set<UUID> matches = new LinkedHashSet<>();
        terms.forEach((id, term) -> {
            if (!term.isBlank() && folded.contains(term.toLowerCase(Locale.ROOT))) matches.add(id);
        });
        Set<String> references = new LinkedHashSet<>();
        document.links().forEach(value -> addReference(references, value));
        var matcher = REFERENCES.matcher(content);
        while (matcher.find()) {
            String value = matcher.group(1) != null ? matcher.group(1)
                    : matcher.group(2) != null ? matcher.group(2) : matcher.group(3);
            addReference(references, value);
            if (references.size() >= MAX_REFERENCES) {
                truncated = true;
                break;
            }
        }
        return new DocumentEvidence(references, terms.keySet(), matches, !truncated && document.complete(), true, eTag,
                fingerprints(folded));
    }

    private static Set<String> fingerprints(String folded) {
        var smallest = new TreeSet<Long>();
        long[] window = new long[4];
        var words = WORDS.matcher(folded);
        int position = 0;
        while (words.find()) {
            long word = hash(folded, words.start(), words.end());
            window[position++ % window.length] = word;
            if (position < window.length) continue;
            long phrase = 0xcbf29ce484222325L;
            for (int index = 0; index < window.length; index++) {
                phrase = (phrase ^ window[(position + index) % window.length]) * 0x100000001b3L;
            }
            smallest.add(phrase);
            if (smallest.size() > MAX_FINGERPRINTS) smallest.pollLast();
        }
        var result = new LinkedHashSet<String>();
        smallest.forEach(hash -> result.add(HexFormat.of().toHexDigits(hash)));
        var ids = IDENTIFIERS.matcher(folded);
        int matches = 0;
        while (matches < 32 && ids.find()) {
            String id = ids.group(2).replaceFirst("[./-]+$", "");
            if (id.length() < 4 || id.chars().noneMatch(Character::isDigit)) continue;
            String kind = switch (ids.group(1)) {
                case "договор" -> "contract";
                case "проект" -> "project";
                case "заказ" -> "order";
                default -> ids.group(1);
            };
            String key = kind + ":" + id;
            if (result.add("id:" + HexFormat.of().toHexDigits(hash(key, 0, key.length())))) matches++;
        }
        return result;
    }

    private static long hash(String text, int start, int end) {
        long value = 0xcbf29ce484222325L;
        for (int index = start; index < end; index++) {
            value = (value ^ text.charAt(index)) * 0x100000001b3L;
        }
        return value;
    }

    private DocumentText plainText() {
        byte[] value = bytes.toByteArray();
        var charset = value.length >= 2 && ((value[0] == (byte) 0xff && value[1] == (byte) 0xfe)
                || (value[0] == (byte) 0xfe && value[1] == (byte) 0xff))
                ? StandardCharsets.UTF_16 : StandardCharsets.UTF_8;
        try {
            return new DocumentText(charset.newDecoder().decode(java.nio.ByteBuffer.wrap(value)).toString(), Set.of(), true);
        } catch (java.nio.charset.CharacterCodingException exception) {
            return new DocumentText(new String(value, charset), Set.of(), false);
        }
    }

    private static void addReference(Set<String> references, String value) {
        String path = value.split("[?#]", 2)[0].strip();
        if (path.isEmpty() || path.length() > 2048 || path.startsWith("//")
                || path.indexOf(':') >= 0 && !path.startsWith("s3://") && !path.startsWith("file:///")) return;
        references.add(path);
    }
}
