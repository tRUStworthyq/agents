package com.trustworthyq.agents.collection.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.util.UUID;

@JsonIgnoreProperties(ignoreUnknown = true)
public record AgentRequest(UUID requestId, UUID id, UUID sourceId, String config) {
}
