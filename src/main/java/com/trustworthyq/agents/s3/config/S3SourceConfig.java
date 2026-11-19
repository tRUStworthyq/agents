package com.trustworthyq.agents.s3.config;

import java.net.URI;
import java.time.Instant;

public record S3SourceConfig(URI endpoint, String region, String bucket, String prefix,
                      String accessKey, String secretKey, String sessionToken, AuditLog auditLog, String archiveBucket) {
    public S3SourceConfig {
        if (endpoint == null || endpoint.getHost() == null || endpoint.getUserInfo() != null
                || endpoint.getQuery() != null || endpoint.getFragment() != null
                || !("http".equals(endpoint.getScheme()) || "https".equals(endpoint.getScheme()))) {
            throw new IllegalArgumentException("S3 endpoint must be an HTTP(S) URI");
        }
        require(bucket);
        require(accessKey);
        require(secretKey);
        region = region == null || region.isBlank() ? "us-east-1" : region;
        prefix = prefix == null ? "" : prefix;
    }

    public record AuditLog(String bucket, String key, Instant coverageStart, Instant coverageEnd) {
        public AuditLog {
            require(bucket);
            require(key);
            if ((coverageStart == null) != (coverageEnd == null)
                    || (coverageStart != null && !coverageStart.isBefore(coverageEnd))) {
                throw new IllegalArgumentException("Invalid audit coverage interval");
            }
        }
    }

    private static void require(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required S3 configuration value");
        }
    }
}
