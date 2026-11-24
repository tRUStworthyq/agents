package com.trustworthyq.agents.collection.listener;

import com.trustworthyq.agents.collection.dto.AgentRequest;
import com.trustworthyq.agents.collection.dto.AgentResponse;
import com.trustworthyq.agents.collection.dto.ObjectMetadata;
import com.trustworthyq.agents.collection.exception.CollectionException;
import com.trustworthyq.agents.collection.service.SourceCollector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
class CollectionListener {
    private static final Logger LOG = LoggerFactory.getLogger(CollectionListener.class);

    private final Map<UUID, SourceCollector> collectors;
    private final JsonMapper json;
    private final KafkaTemplate<String, String> kafka;
    private final String responseTopic;
    private final int batchSize;

    CollectionListener(List<SourceCollector> collectors, JsonMapper json, KafkaTemplate<String, String> kafka,
                       @Value("${app.kafka.response-topic}") String responseTopic,
                       @Value("${app.kafka.batch-size}") int batchSize) {
        if (batchSize < 1) {
            throw new IllegalArgumentException("app.kafka.batch-size must be positive");
        }
        this.collectors = collectors.stream().collect(Collectors.toUnmodifiableMap(
                SourceCollector::sourceId, Function.identity()));
        this.json = json;
        this.kafka = kafka;
        this.responseTopic = responseTopic;
        this.batchSize = batchSize;
    }

    @KafkaListener(topics = "${app.kafka.request-topic}")
    public void collect(String payload) {
        AgentRequest request;
        try {
            request = json.readValue(payload, AgentRequest.class);
        } catch (JacksonException exception) {
            LOG.warn("Discarding malformed collection request");
            return;
        }
        if (request == null || request.requestId() == null) {
            LOG.warn("Discarding collection request without requestId");
            return;
        }

        var output = new BatchOutput(request);
        var collector = request.sourceId() == null ? null : collectors.get(request.sourceId());
        if (collector == null) {
            output.finish("UNSUPPORTED_SOURCE");
            return;
        }
        if (request.id() == null || request.config() == null || request.config().isBlank()) {
            output.finish("INVALID_REQUEST");
            return;
        }

        String error = null;
        try {
            collector.collect(request.config(), request.contentRules() == null ? Map.of() : request.contentRules(), output::add);
        } catch (PublishException exception) {
            throw exception;
        } catch (IOException | RuntimeException exception) {
            error = exception instanceof CollectionException failure ? failure.code() : "COLLECTION_FAILED";
            LOG.warn("Collection {} failed with {} ({})", request.requestId(), error,
                    exception.getClass().getSimpleName());
        }
        output.finish(error);
    }

    private class BatchOutput {
        private final AgentRequest request;
        private final List<ObjectMetadata> items = new ArrayList<>();
        private long batchIndex;

        BatchOutput(AgentRequest request) {
            this.request = request;
        }

        void add(ObjectMetadata item) {
            items.add(item);
            if (items.size() == batchSize) {
                flush();
            }
        }

        void finish(String error) {
            flush();
            send(error == null ? AgentResponse.Status.COMPLETED : AgentResponse.Status.FAILED, error);
        }

        private void flush() {
            if (!items.isEmpty()) {
                send(AgentResponse.Status.BATCH, null);
                items.clear();
                batchIndex++;
            }
        }

        private void send(AgentResponse.Status status, String error) {
            var response = new AgentResponse(request.requestId(), request.id(), request.sourceId(),
                    batchIndex, status, List.copyOf(items), error);
            try {
                kafka.send(responseTopic, request.requestId().toString(), json.writeValueAsString(response)).join();
            } catch (RuntimeException exception) {
                Throwable cause = exception instanceof CompletionException ? exception.getCause() : exception;
                throw new PublishException("Could not publish collection response " + request.requestId(), cause);
            }
        }
    }

    private static class PublishException extends RuntimeException {
        PublishException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
