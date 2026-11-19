package com.trustworthyq.agents.pii.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Set;

public record PiiResult(Status status, Set<String> categories, Set<String> detectors,
                        @JsonProperty("scan_complete") boolean scanComplete,
                        @JsonProperty("scanner_version") String scannerVersion) {
    public enum Status {
        DETECTED, REVIEW_REQUIRED, NOT_DETECTED, PARTIAL, UNSUPPORTED, ERROR, NOT_SCANNED
    }
}
