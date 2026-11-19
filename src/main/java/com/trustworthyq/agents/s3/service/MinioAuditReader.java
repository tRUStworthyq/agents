package com.trustworthyq.agents.s3.service;

import com.trustworthyq.agents.collection.dto.ObjectMetadata;
import com.trustworthyq.agents.s3.config.S3SourceConfig;

import org.springframework.stereotype.Component;
import software.amazon.awssdk.services.s3.S3Client;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
class MinioAuditReader {
    private final JsonMapper json;

    MinioAuditReader(JsonMapper json) {
        this.json = json;
    }

    Map<String, ObjectMetadata.AccessStatistics> read(S3Client client, S3SourceConfig config) throws IOException {
        if (config.auditLog() == null) {
            return Map.of();
        }

        var log = config.auditLog();
        Map<String, ObjectMetadata.AccessStatistics> statistics = new HashMap<>();
        try (var body = client.getObject(request -> request.bucket(log.bucket()).key(log.key()));
             var lines = new BufferedReader(new InputStreamReader(body, StandardCharsets.UTF_8))) {
            String line;
            while ((line = lines.readLine()) != null) {
                if (!line.isBlank()) {
                    addRead(statistics, json.readTree(line), config);
                }
            }
        }
        return statistics;
    }

    private void addRead(Map<String, ObjectMetadata.AccessStatistics> statistics, JsonNode event,
                         S3SourceConfig config) {
        JsonNode api = event.path("api");
        String key = api.path("object").asString("");
        int status = api.path("statusCode").asInt(0);
        if (!"GetObject".equals(api.path("name").asString("")) || status < 200 || status >= 300
                || !config.bucket().equals(api.path("bucket").asString("")) || key.isEmpty()
                || !key.startsWith(config.prefix())) {
            return;
        }

        Instant time = Instant.parse(event.path("time").asString(""));
        var coverageStart = config.auditLog().coverageStart();
        var coverageEnd = config.auditLog().coverageEnd();
        if (coverageStart != null && (time.isBefore(coverageStart) || time.isAfter(coverageEnd))) {
            return;
        }
        statistics.compute(key, (unused, previous) -> previous == null
                ? new ObjectMetadata.AccessStatistics(1, time, coverageStart, coverageEnd)
                : new ObjectMetadata.AccessStatistics(previous.successfulReads() + 1,
                        time.isAfter(previous.lastReadTime()) ? time : previous.lastReadTime(), coverageStart, coverageEnd));
    }
}
