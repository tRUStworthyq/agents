package com.trustworthyq.agents.collection.service;

import com.trustworthyq.agents.collection.dto.ObjectMetadata;

import java.io.IOException;
import java.util.UUID;
import java.util.function.Consumer;

public interface SourceCollector {
    UUID sourceId();

    default void collect(String config, Consumer<ObjectMetadata> output) throws IOException {
        collect(config, java.util.Map.of(), output);
    }

    void collect(String config, java.util.Map<UUID, String> contentRules, Consumer<ObjectMetadata> output) throws IOException;
}
