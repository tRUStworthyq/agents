package com.trustworthyq.agents.s3.service;

import com.trustworthyq.agents.collection.service.ContentHashes;

import com.sun.net.httpserver.HttpServer;
import com.trustworthyq.agents.collection.dto.ObjectMetadata;
import com.trustworthyq.agents.pii.config.PiiProperties;
import com.trustworthyq.agents.pii.dto.PiiResult;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class S3CollectorPiiTest {
    @Test
    void readsObjectOncePerScanAndPreservesHashAndWireCompatibility() throws Exception {
        byte[] body = "test@example.test\n".getBytes(StandardCharsets.UTF_8);
        var getCount = new AtomicInteger();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/documents", exchange -> {
            try (exchange) {
                String query = exchange.getRequestURI().getRawQuery();
                if (query != null && query.contains("list-type=2")) {
                    byte[] listing = """
                            <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
                              <IsTruncated>false</IsTruncated>
                              <Contents><Key>test.txt</Key><ETag>"fixture"</ETag><Size>%d</Size></Contents>
                            </ListBucketResult>
                            """.formatted(body.length).getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(200, listing.length);
                    exchange.getResponseBody().write(listing);
                } else if (query != null && query.contains("acl")) {
                    exchange.sendResponseHeaders(403, -1);
                } else {
                    getCount.incrementAndGet();
                    exchange.getResponseHeaders().add("Content-Type", "text/plain; charset=utf-8");
                    exchange.sendResponseHeaders(200, body.length);
                    exchange.getResponseBody().write(body);
                }
            }
        });
        server.start();
        var metrics = new SimpleMeterRegistry();
        try {
            var mapper = JsonMapper.builder().build();
            String config = mapper.writeValueAsString(Map.of(
                    "endpoint", "http://127.0.0.1:" + server.getAddress().getPort(), "bucket", "documents",
                    "accessKey", "fixture", "secretKey", "fixture"));
            var items = new ArrayList<ObjectMetadata>();
            String sha256 = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
            for (boolean enabled : new boolean[]{true, false}) {
                var properties = new PiiProperties(enabled, 256, 1024, Set.of("EMAIL"));
                new S3Collector(mapper, new MinioAuditReader(mapper), properties, metrics)
                        .collect(config, items::add);
                assertThat(getCount.get()).isEqualTo(items.size());
                assertThat(items.getLast().sha256()).isEqualTo(sha256);
            }
            assertThat(getCount.get()).isEqualTo(2);
            assertThat(items.getFirst().pii().status()).isEqualTo(PiiResult.Status.DETECTED);
            assertThat(mapper.writeValueAsString(items.getFirst())).contains("\"pii\"")
                    .doesNotContain("test@example.test");
            assertThat(mapper.writeValueAsString(items.getLast())).doesNotContain("\"pii\"");
        } finally {
            metrics.close();
            server.stop(0);
        }
    }

    @Test
    void refusesToReturnHashAfterShortRead() {
        assertThatThrownBy(() -> ContentHashes.read(new ByteArrayInputStream(new byte[3]), 4, null, null))
                .isInstanceOf(IOException.class);
    }
}
