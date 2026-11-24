package com.trustworthyq.agents.collection.dto;

import java.util.Set;
import java.util.UUID;

public record DocumentEvidence(Set<String> references, Set<UUID> evaluatedRules, Set<UUID> matchingRules,
                               boolean complete, boolean text, String eTag, Set<String> textFingerprints) {
}
