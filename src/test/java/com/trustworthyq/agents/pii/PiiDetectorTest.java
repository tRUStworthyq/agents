package com.trustworthyq.agents.pii;

import com.trustworthyq.agents.pii.config.PiiProperties;
import com.trustworthyq.agents.pii.dto.PiiResult;
import com.trustworthyq.agents.pii.service.PiiDetector;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import static com.trustworthyq.agents.pii.dto.PiiResult.Status.*;
import static org.assertj.core.api.Assertions.assertThat;

class PiiDetectorTest {
    private static final Set<String> RULES = Set.of("EMAIL", "PHONE_RU", "SNILS", "INN_12", "PASSPORT_RU");

    @Test
    void scansEveryByteBoundaryIncludingUtf8AndBom() {
        var result = scan("\uFEFFПаспорт: 12 34 567890; example@example.test; +7 (999) 000-12-34;"
                + " 112-233-445 95; 500100732259", "txt", 10_000);
        assertThat(result.status()).isEqualTo(DETECTED);
        assertThat(result.scanComplete()).isTrue();
        assertThat(result.categories()).containsExactlyInAnyOrderElementsOf(RULES);
        assertThat(JsonMapper.builder().build().writeValueAsString(result))
                .contains("scan_complete", "scanner_version")
                .doesNotContain("example@example.test", "567890", "445 95", "500100732259", "000-12-34");
    }

    @Test
    void rejectsBadChecksumsAndMalformedAddresses() {
        var result = scan("112-233-445 96; 500100732258; bad..name@example.test; +7 (999 000-12-34",
                "csv", 10_000);
        assertThat(result.status()).isEqualTo(NOT_DETECTED);
        assertThat(result.categories()).isEmpty();
    }

    @Test
    void requestsReviewForPassportWithoutContext() {
        assertThat(scan("order 12 34 567890", "json", 10_000).status()).isEqualTo(REVIEW_REQUIRED);
    }

    @Test
    void classifiesEmptyUnsupportedAndDisabledInputs() {
        assertThat(scan("", "xml", 100).status()).isEqualTo(NOT_DETECTED);
        assertThat(scan("x@example.test", "pdf", 100).status()).isEqualTo(UNSUPPORTED);
        assertThat(scan("\u0000x@example.test", "txt", 100).status()).isEqualTo(UNSUPPORTED);
        var detector = new PiiDetector(new PiiProperties(true, 256, 100, RULES), "txt", "text/plain");
        byte[] content = "x@example.test".getBytes(StandardCharsets.UTF_16);
        detector.feed(content, content.length);
        assertThat(detector.finish().status()).isEqualTo(UNSUPPORTED);
        assertThat(new PiiDetector(new PiiProperties(false, 256, 100, RULES), "txt", null).finish().status())
                .isEqualTo(NOT_SCANNED);
    }

    @Test
    void keepsConfirmedMatchesWhenLimited() {
        String content = "example@example.test; " + "x ".repeat(10_000);
        var found = scan(content, "txt", 100);
        assertThat(found.status()).isEqualTo(DETECTED);
        assertThat(found.scanComplete()).isFalse();
        assertThat(scan(content, "txt", 15).status()).isEqualTo(PARTIAL);
        assertThat(scan("x ".repeat(10_000), "txt", 100_000).status()).isEqualTo(NOT_DETECTED);
    }

    @Test
    void reportsDetectorErrorWithoutText() {
        var detector = new PiiDetector(new PiiProperties(true, 256, 100, RULES), "txt", null);
        detector.feed(new byte[0], 1);
        assertThat(detector.finish().status()).isEqualTo(ERROR);
    }

    @Test
    void retainsContextWhileSlidingAndAcceptsAnObjectExactlyAtTheLimit() {
        String text = "x ".repeat(300) + "Паспорт: 12 34 567890; " + "x ".repeat(300);
        var result = scan(text, "txt", text.getBytes(StandardCharsets.UTF_8).length);
        assertThat(result.status()).isEqualTo(DETECTED);
        assertThat(result.scanComplete()).isTrue();
        assertThat(result.categories()).containsExactly("PASSPORT_RU");
    }

    @Test
    void acceptsInnWithLeadingZeroInRegionCode() {
        assertThat(scan("010000000102", "txt", 100).categories()).containsExactly("INN_12");
    }

    private PiiResult scan(String text, String extension, long limit) {
        var detector = new PiiDetector(new PiiProperties(true, 256, limit, RULES), extension, null);
        for (byte value : text.getBytes(StandardCharsets.UTF_8)) {
            detector.feed(new byte[]{value}, 1);
        }
        return detector.finish();
    }
}
