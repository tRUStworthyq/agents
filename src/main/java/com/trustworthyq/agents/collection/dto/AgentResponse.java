package com.trustworthyq.agents.collection.dto;

import java.util.List;
import java.util.UUID;

public record AgentResponse(UUID requestId, UUID id, UUID sourceId, long batchIndex,
                     Status status, List<ObjectMetadata> items, String error) {
    public enum Status {
        BATCH, COMPLETED, FAILED
    }
}
