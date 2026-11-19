package com.trustworthyq.agents.pii.service;

import com.trustworthyq.agents.pii.config.PiiProperties;
import com.trustworthyq.agents.pii.dto.PiiResult;
import com.trustworthyq.agents.pii.dto.PiiRule;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import static com.trustworthyq.agents.pii.dto.PiiResult.Status.*;

public final class PiiDetector {
    private static final int CONTEXT = 48;
    private static final Set<String> EXTENSIONS = Set.of("txt", "csv", "json", "xml");
    private final PiiProperties config;
    private final EnumSet<PiiRule> confirmed = EnumSet.noneOf(PiiRule.class);
    private final EnumSet<PiiRule> review = EnumSet.noneOf(PiiRule.class);
    private final Set<PiiRule> rules;
    private final StringBuilder window = new StringBuilder();
    private final java.nio.charset.CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder();
    private final ByteBuffer trailing = ByteBuffer.allocate(4);
    private PiiResult.Status stopped;
    private long bytes;
    private int checked;
    private boolean firstCharacter = true;

    public PiiDetector(PiiProperties config, String extension, String contentType) {
        this.config = config;
        this.rules = config.enabledDetectors().stream().map(PiiRule::valueOf).collect(Collectors.toSet());
        String type = contentType == null ? "" : contentType.toLowerCase(Locale.ROOT);
        if (!config.enabled() || rules.isEmpty()) {
            stopped = NOT_SCANNED;
        } else if (!EXTENSIONS.contains(extension.toLowerCase(Locale.ROOT))
                || !supportedContentType(type)) {
            stopped = UNSUPPORTED;
        }
    }

    private static boolean supportedContentType(String type) {
        String[] parts = type.split(";");
        String media = parts[0].strip();
        if (!(media.isEmpty() || media.startsWith("text/") || media.equals("application/json")
                || media.equals("application/xml") || media.equals("application/octet-stream"))) {
            return false;
        }
        for (String part : parts) {
            String parameter = part.strip().replace(" ", "").replace("\"", "");
            if (parameter.startsWith("charset=") && !parameter.equals("charset=utf-8")) {
                return false;
            }
        }
        return true;
    }

    public void feed(byte[] chunk, int length) {
        if (stopped != null) {
            return;
        }
        int accepted = (int) Math.min(length, config.maxScanBytes() - bytes);
        bytes += accepted;
        try {
            decode(chunk, accepted, false);
            if (stopped == null && accepted < length) {
                stopped = PARTIAL;
            }
        } catch (RuntimeException error) {
            stopped = ERROR;
        }
    }

    public PiiResult finish() {
        try {
            if (stopped == null) {
                decode(new byte[0], 0, true);
            }
            if (stopped == PARTIAL) {
                scan(true);
            }
        } catch (RuntimeException error) {
            stopped = ERROR;
        }
        boolean complete = stopped == null;
        window.setLength(0);
        trailing.clear();
        EnumSet<PiiRule> found = EnumSet.copyOf(confirmed);
        found.addAll(review);
        var status = !confirmed.isEmpty() ? DETECTED
                : stopped == ERROR ? ERROR
                : !review.isEmpty() ? REVIEW_REQUIRED
                : complete ? NOT_DETECTED : stopped;
        return new PiiResult(status, found.stream().map(Enum::name).collect(Collectors.toUnmodifiableSet()),
                found.stream().map(PiiRule::method).collect(Collectors.toUnmodifiableSet()), complete, "1.0");
    }

    private void decode(byte[] chunk, int size, boolean end) {
        trailing.flip();
        ByteBuffer input = ByteBuffer.allocate(trailing.remaining() + size);
        input.put(trailing).put(chunk, 0, size).flip();
        trailing.clear();
        CharBuffer output = CharBuffer.allocate(input.remaining());
        var result = decoder.decode(input, output, end);
        if (result.isError()) {
            stopped = UNSUPPORTED;
            return;
        }
        trailing.put(input);
        output.flip();
        while (output.hasRemaining()) {
            char character = output.get();
            if (firstCharacter) {
                firstCharacter = false;
                if (character == '\uFEFF') {
                    continue;
                }
            }
            if (Character.isISOControl(character) && character != '\t'
                    && character != '\r' && character != '\n') {
                stopped = UNSUPPORTED;
                return;
            }
            window.append(character);
        }
        scan(end);
    }

    private void scan(boolean end) {
        // Hold enough text for the longest email, passport context, and the right boundary.
        int pending = Math.max(config.chunkOverlapChars(), 384);
        int limit = end ? window.length() : Math.max(checked, window.length() - pending);
        for (PiiRule rule : rules) {
            if (confirmed.contains(rule)) {
                continue;
            }
            var matcher = rule.pattern().matcher(window)
                    .region(checked, window.length()).useTransparentBounds(true);
            while (matcher.find() && matcher.start() < limit) {
                if ((stopped == null || matcher.end() < window.length()) && rule.matches(matcher.group())) {
                    var context = window.subSequence(Math.max(0, matcher.start() - CONTEXT),
                            Math.min(window.length(), matcher.end() + CONTEXT));
                    if (rule.requiresReview(context)) {
                        review.add(rule);
                    } else {
                        confirmed.add(rule);
                        break;
                    }
                }
            }
        }
        int remove = Math.max(0, limit - CONTEXT);
        window.delete(0, remove);
        checked = limit - remove;
    }
}
