package com.trustworthyq.agents.collection.service;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionLaunch;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionRemoteGoTo;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.apache.pdfbox.text.PDFTextStripper;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Writer;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.zip.ZipInputStream;

record DocumentText(String content, Set<String> links, boolean complete) {
    private static final int MAX_EXPANDED_BYTES = 8 * 1024 * 1024;
    private static final int MAX_TEXT = 2 * 1024 * 1024;
    private static final int MAX_PAGES = 300;
    private static final int MAX_LINKS = 2000;

    static DocumentText pdf(byte[] bytes) {
        StringBuilder text = new StringBuilder();
        Set<String> links = new LinkedHashSet<>();
        try (var document = Loader.loadPDF(bytes)) {
            int pages = Math.min(document.getNumberOfPages(), MAX_PAGES);
            var stripper = new PDFTextStripper();
            stripper.setEndPage(pages);
            stripper.writeText(document, new Writer() {
                @Override
                public void write(char[] value, int offset, int length) throws IOException {
                    if (length > MAX_TEXT - text.length()) throw new IOException("Document text limit");
                    text.append(value, offset, length);
                }

                @Override public void flush() {}
                @Override public void close() {}
            });
            for (int page = 0; page < pages; page++) {
                for (var annotation : document.getPage(page).getAnnotations()) {
                    if (!(annotation instanceof PDAnnotationLink link)) continue;
                    String target = switch (link.getAction()) {
                        case PDActionURI uri -> uri.getURI();
                        case PDActionRemoteGoTo remote when remote.getFile() != null -> remote.getFile().getFile();
                        case PDActionLaunch launch when launch.getFile() != null -> launch.getFile().getFile();
                        case null, default -> null;
                    };
                    if (target != null) links.add(target);
                    if (links.size() >= MAX_LINKS) return new DocumentText(text.toString(), links, false);
                }
            }
            return new DocumentText(text.toString(), links, pages == document.getNumberOfPages());
        } catch (IOException | RuntimeException exception) {
            return new DocumentText(text.toString(), links, false);
        }
    }

    static DocumentText office(byte[] bytes) {
        var factory = XMLInputFactory.newFactory();
        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        StringBuilder text = new StringBuilder();
        Set<String> links = new LinkedHashSet<>();
        int remaining = MAX_EXPANDED_BYTES;
        boolean officePackage = false;
        try (var zip = new ZipInputStream(new ByteArrayInputStream(bytes))) {
            for (var entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
                byte[] xml = zip.readNBytes(remaining + 1);
                remaining -= xml.length;
                if (remaining < 0) return new DocumentText(text.toString(), links, false);
                officePackage |= "[Content_Types].xml".equals(entry.getName());
                if (!(entry.getName().endsWith(".xml") || entry.getName().endsWith(".rels"))) continue;
                var reader = factory.createXMLStreamReader(new ByteArrayInputStream(xml));
                try {
                    while (reader.hasNext()) {
                        int event = reader.next();
                        if (event == XMLStreamConstants.CHARACTERS) {
                            text.append(reader.getText());
                        } else if (event == XMLStreamConstants.START_ELEMENT && "Relationship".equals(reader.getLocalName())) {
                            String target = reader.getAttributeValue(null, "Target");
                            if (target != null && "External".equals(reader.getAttributeValue(null, "TargetMode"))) links.add(target);
                        } else if (event == XMLStreamConstants.END_ELEMENT
                                && Set.of("p", "si", "row").contains(reader.getLocalName())) {
                            text.append('\n');
                        }
                        if (text.length() > MAX_TEXT || links.size() >= MAX_LINKS) {
                            return new DocumentText(text.toString(), links, false);
                        }
                    }
                } finally {
                    reader.close();
                }
            }
            return new DocumentText(text.toString(), links, officePackage);
        } catch (IOException | XMLStreamException exception) {
            return new DocumentText(text.toString(), links, false);
        }
    }
}
