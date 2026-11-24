package com.trustworthyq.agents.collection.service;

import org.junit.jupiter.api.Test;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.assertj.core.api.Assertions.assertThat;

class DocumentScannerTest {
    @Test
    void identifiesSharedFragmentsAndProjectCodesAcrossDocuments() {
        var first = scan("Проект № DACS-417. Подготовить подробный отчёт о состоянии оборудования на основной площадке.");
        var second = scan("Project # DACS-417. Просьба подготовить подробный отчёт о состоянии оборудования на основной площадке.");
        assertThat(first.stream().filter(second::contains)).anyMatch(value -> value.startsWith("id:"));
        assertThat(first.stream().filter(second::contains).filter(value -> !value.startsWith("id:")).count()).isGreaterThanOrEqualTo(3);
    }

    private java.util.Set<String> scan(String text) {
        var scanner = new DocumentScanner("txt", null, Map.of());
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        scanner.feed(bytes, bytes.length);
        return scanner.finish(null).textFingerprints();
    }

    @Test
    void extractsLinksAndTemplateMatchesWithoutPersistingText() {
        UUID contract = UUID.randomUUID();
        UUID invoice = UUID.randomUUID();
        var scanner = new DocumentScanner("md", null, Map.of(contract, "ДОГОВОР", invoice, "счёт"));
        byte[] text = "Договор и [приложение](../docs/appendix.pdf). См. budget.csv.".getBytes(StandardCharsets.UTF_8);
        scanner.feed(text, text.length);

        var evidence = scanner.finish("etag");
        assertThat(evidence.references()).contains("../docs/appendix.pdf", "budget.csv");
        assertThat(evidence.evaluatedRules()).containsExactlyInAnyOrder(contract, invoice);
        assertThat(evidence.matchingRules()).containsExactly(contract);
        assertThat(evidence.complete()).isTrue();
    }

    @Test
    void readsOfficeTextAndExternalRelationshipTargets() throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var zip = new ZipOutputStream(bytes)) {
            zip.putNextEntry(new ZipEntry("[Content_Types].xml"));
            zip.write("<Types/>".getBytes(StandardCharsets.UTF_8));
            zip.putNextEntry(new ZipEntry("word/document.xml"));
            zip.write("<document><p><t>Договор</t></p></document>".getBytes(StandardCharsets.UTF_8));
            zip.putNextEntry(new ZipEntry("word/_rels/document.xml.rels"));
            zip.write("<Relationships><Relationship Target='../contract.pdf' TargetMode='External'/></Relationships>"
                    .getBytes(StandardCharsets.UTF_8));
        }
        UUID rule = UUID.randomUUID();
        var scanner = new DocumentScanner("docx", null, Map.of(rule, "договор"));
        scanner.feed(bytes.toByteArray(), bytes.size());

        var evidence = scanner.finish("etag");
        assertThat(evidence.complete()).isTrue();
        assertThat(evidence.matchingRules()).containsExactly(rule);
        assertThat(evidence.references()).containsExactly("../contract.pdf");
    }

    @Test
    void readsPdfLinkAnnotationsWithoutResolvingExternalUrls() throws IOException {
        var bytes = new ByteArrayOutputStream();
        try (var document = new PDDocument()) {
            var page = new PDPage();
            document.addPage(page);
            var link = new PDAnnotationLink();
            var action = new PDActionURI();
            action.setURI("s3://docs/contracts/contract.pdf");
            link.setAction(action);
            page.getAnnotations().add(link);
            document.save(bytes);
        }
        var scanner = new DocumentScanner("pdf", null, Map.of());
        scanner.feed(bytes.toByteArray(), bytes.size());

        var evidence = scanner.finish("etag");
        assertThat(evidence.complete()).isTrue();
        assertThat(evidence.references()).containsExactly("s3://docs/contracts/contract.pdf");
    }
}
