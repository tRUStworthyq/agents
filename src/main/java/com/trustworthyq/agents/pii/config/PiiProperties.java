package com.trustworthyq.agents.pii.config;

import com.trustworthyq.agents.pii.dto.PiiRule;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Set;

@ConfigurationProperties("app.pii")
public record PiiProperties(boolean enabled, int chunkOverlapChars, long maxScanBytes,
                            Set<String> enabledDetectors) {
    public PiiProperties {
        if (chunkOverlapChars < 256 || maxScanBytes < 1) {
            throw new IllegalArgumentException("Invalid PII scan limits");
        }
        enabledDetectors = Set.copyOf(enabledDetectors);
        enabledDetectors.forEach(PiiRule::valueOf);
    }
}
