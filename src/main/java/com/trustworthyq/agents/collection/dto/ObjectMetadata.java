package com.trustworthyq.agents.collection.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.trustworthyq.agents.pii.dto.PiiResult;

import java.time.Instant;
import java.util.List;

public record ObjectMetadata(String path, String extension, long sizeBytes, Instant creationTime,
                      Instant modificationTime, Instant lastAccessTime, Owner owner,
                      List<AccessGrant> accessRights, String sha256, String simhash,
                      AccessStatistics accessStatistics,
                      @JsonInclude(JsonInclude.Include.NON_NULL) PiiResult pii) {
    public record Owner(String id, String displayName) {
    }

    public record AccessGrant(String type, String principal, String permission) {
    }

    public record AccessStatistics(long successfulReads, Instant lastReadTime, Instant coverageStart, Instant coverageEnd) {
    }
}
