package com.trustworthyq.agents.collection.service;

import com.trustworthyq.agents.collection.dto.ObjectMetadata;

import java.io.IOException;
import java.util.UUID;
import java.util.function.Consumer;

public interface SourceCollector {
    UUID sourceId();

    void collect(String config, Consumer<ObjectMetadata> output) throws IOException;
}
