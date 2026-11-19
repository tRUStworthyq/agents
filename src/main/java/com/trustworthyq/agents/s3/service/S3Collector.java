package com.trustworthyq.agents.s3.service;

import com.trustworthyq.agents.collection.dto.ObjectMetadata;
import com.trustworthyq.agents.collection.exception.CollectionException;
import com.trustworthyq.agents.collection.service.SourceCollector;
import com.trustworthyq.agents.s3.config.S3SourceConfig;
import com.trustworthyq.agents.pii.service.PiiDetector;
import com.trustworthyq.agents.pii.config.PiiProperties;
import com.trustworthyq.agents.pii.dto.PiiResult;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectAclResponse;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.UUID;
import java.util.function.Consumer;

@Component
class S3Collector implements SourceCollector {
    private static final UUID SOURCE_ID = UUID.fromString("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a14");

    private final JsonMapper json;
    private final MinioAuditReader auditReader;
    private final PiiProperties piiProperties;
    private final Timer piiTime;
    private final MeterRegistry metrics;

    S3Collector(JsonMapper json, MinioAuditReader auditReader, PiiProperties piiProperties, MeterRegistry metrics) {
        this.json = json;
        this.auditReader = auditReader;
        this.piiProperties = piiProperties;
        this.metrics = metrics;
        this.piiTime = metrics.timer("dacs.s3.pii.chunk");
    }

    @Override
    public UUID sourceId() {
        return SOURCE_ID;
    }

    @Override
    public void collect(String configJson, Consumer<ObjectMetadata> output) throws IOException {
        S3SourceConfig config = json.readValue(configJson, S3SourceConfig.class);
        try (S3Client client = authenticate(config)) {
            var statistics = auditReader.read(client, config);
            var objects = client.listObjectsV2Paginator(request -> request.bucket(config.bucket())
                    .prefix(config.prefix()).fetchOwner(true)).contents();

            for (S3Object object : objects) {
                var access = config.auditLog() == null ? null : statistics.getOrDefault(
                        object.key(), new ObjectMetadata.AccessStatistics(0, null, config.auditLog().coverageStart(), config.auditLog().coverageEnd()));
                output.accept(readObject(client, config.bucket(), object, access));
            }
        } catch (S3Exception exception) {
            throw new CollectionException("S3_HTTP_" + exception.statusCode(), exception);
        }
    }

    private S3Client authenticate(S3SourceConfig config) {
        String token = config.sessionToken();
        var credentials = token == null || token.isBlank()
                ? AwsBasicCredentials.create(config.accessKey(), config.secretKey())
                : AwsSessionCredentials.create(config.accessKey(), config.secretKey(), token);
        return S3Client.builder()
                .endpointOverride(config.endpoint())
                .region(Region.of(config.region()))
                .credentialsProvider(StaticCredentialsProvider.create(credentials))
                .forcePathStyle(true)
                .overrideConfiguration(options -> options.apiCallTimeout(Duration.ofMinutes(10))
                        .apiCallAttemptTimeout(Duration.ofMinutes(5)))
                .build();
    }

    private ObjectMetadata readObject(S3Client client, String bucket, S3Object object,
                                      ObjectMetadata.AccessStatistics statistics) throws IOException {
        ContentHashes hashes;
        PiiResult pii;
        String extension = extension(object.key());
        GetObjectResponse response;
        try (var body = client.getObject(request -> request.bucket(bucket).key(object.key()).ifMatch(object.eTag()))) {
            response = body.response();
            var detector = piiProperties.enabled() ? new PiiDetector(piiProperties, extension, response.contentType()) : null;
            var sample = Timer.start(metrics);
            try {
                hashes = ContentHashes.read(body, response.contentLength(), detector, piiTime);
                pii = detector == null ? null : piiTime.record(detector::finish);
            } finally {
                sample.stop(metrics.timer("dacs.s3.object.read", "pii", Boolean.toString(detector != null)));
            }
        }

        var acl = readAcl(client, bucket, object.key(), response.versionId());
        var owner = acl == null || acl.owner() == null || acl.owner().id() == null
                ? object.owner() : acl.owner();
        var grants = acl == null ? null : acl.grants().stream()
                .filter(grant -> grant.grantee() != null)
                .map(grant -> {
                    var principal = grant.grantee();
                    String identifier = principal.id() != null ? principal.id()
                            : principal.uri() != null ? principal.uri() : principal.emailAddress();
                    return new ObjectMetadata.AccessGrant(principal.typeAsString(), identifier,
                            grant.permissionAsString());
                })
                .filter(grant -> grant.principal() != null && !grant.principal().isBlank())
                .toList();

        Instant lastAccess = readTimestamp(response.metadata().get("last-access-time"));
        if (statistics != null && statistics.lastReadTime() != null
                && (lastAccess == null || statistics.lastReadTime().isAfter(lastAccess))) {
            lastAccess = statistics.lastReadTime();
        }
        return new ObjectMetadata("s3://" + bucket + "/" + object.key(), extension,
                response.contentLength(), readTimestamp(response.metadata().get("creation-time")),
                response.lastModified(), lastAccess,
                owner == null || owner.id() == null || owner.id().isBlank() ? null
                        : new ObjectMetadata.Owner(owner.id(), owner.displayName()),
                grants == null || (!acl.grants().isEmpty() && grants.isEmpty()) ? null : grants,
                hashes.sha256(), hashes.simhash(), statistics, pii);
    }

    private GetObjectAclResponse readAcl(S3Client client, String bucket, String key, String versionId) {
        try {
            return client.getObjectAcl(request -> request.bucket(bucket).key(key).versionId(versionId));
        } catch (S3Exception exception) {
            if (exception.statusCode() == 403 || exception.statusCode() == 405 || exception.statusCode() == 501) {
                return null;
            }
            throw exception;
        }
    }

    private String extension(String key) {
        int dot = key.lastIndexOf('.');
        return dot > key.lastIndexOf('/') + 1 && dot < key.length() - 1 ? key.substring(dot + 1) : "";
    }

    private Instant readTimestamp(String value) {
        try {
            return value == null ? null : Instant.parse(value);
        } catch (DateTimeParseException exception) {
            return null;
        }
    }
}
