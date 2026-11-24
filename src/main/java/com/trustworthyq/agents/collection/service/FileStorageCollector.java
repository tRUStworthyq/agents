package com.trustworthyq.agents.collection.service;

import com.trustworthyq.agents.collection.dto.ObjectMetadata;
import com.trustworthyq.agents.collection.exception.CollectionException;
import com.trustworthyq.agents.pii.config.PiiProperties;
import com.trustworthyq.agents.pii.service.PiiDetector;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Set;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

@Component
class FileStorageCollector implements SourceCollector {
    private static final UUID SOURCE_ID = UUID.fromString("a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a15");
    private static final Set<String> WINDOWS_SYSTEM_DIRECTORIES = Set.of("$RECYCLE.BIN", "System Volume Information");

    private final JsonMapper json;
    private final String rootDirectory;
    private final PiiProperties piiProperties;
    private final Timer piiTime;

    FileStorageCollector(JsonMapper json, @Value("${agents.filesystem.root:}") String rootDirectory,
                         PiiProperties piiProperties, MeterRegistry metrics) {
        this.json = json;
        this.rootDirectory = rootDirectory;
        this.piiProperties = piiProperties;
        this.piiTime = metrics.timer("dacs.filesystem.pii.chunk");
    }

    @Override
    public UUID sourceId() {
        return SOURCE_ID;
    }

    @Override
    public void collect(String configJson, Map<UUID, String> contentRules, Consumer<ObjectMetadata> output) throws IOException {
        if (rootDirectory.isBlank()) {
            throw new CollectionException("FILESYSTEM_NOT_CONFIGURED", null);
        }
        Config config = json.readValue(configJson, Config.class);
        if (config == null || config.directory() == null || config.directory().isBlank()
                || config.directory().matches("(?s)^[A-Za-z]:.*") || config.directory().startsWith("\\")) {
            throw new CollectionException("FILESYSTEM_INVALID_DIRECTORY", null);
        }
        Path relative;
        try {
            relative = Path.of(config.directory());
        } catch (InvalidPathException exception) {
            throw new CollectionException("FILESYSTEM_INVALID_DIRECTORY", exception);
        }
        if (relative.getRoot() != null) {
            throw new CollectionException("FILESYSTEM_INVALID_DIRECTORY", null);
        }
        Path root;
        try {
            root = Path.of(rootDirectory).toRealPath();
        } catch (IOException | InvalidPathException exception) {
            throw new CollectionException("FILESYSTEM_ROOT_UNAVAILABLE", exception);
        }
        Path directory = root.resolve(relative).normalize();
        if (!directory.startsWith(root)
                || !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                || !directory.equals(directory.toRealPath())) {
            throw new CollectionException("FILESYSTEM_INVALID_DIRECTORY", null);
        }
        try {
            walk(root, directory, contentRules, output);
        } catch (AccessDeniedException exception) {
            throw new CollectionException("FILESYSTEM_ACCESS_DENIED", exception);
        } catch (IOException exception) {
            throw new CollectionException("FILESYSTEM_READ_FAILED", exception);
        }
    }

    private void walk(Path root, Path directory, Map<UUID, String> contentRules, Consumer<ObjectMetadata> output) throws IOException {
        Files.walkFileTree(directory, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path path, BasicFileAttributes attributes) throws IOException {
                return !isSystemDirectory(path) && path.equals(path.toRealPath())
                        ? FileVisitResult.CONTINUE : FileVisitResult.SKIP_SUBTREE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path path, IOException exception) throws IOException {
                if (isSystemDirectory(path)) {
                    return FileVisitResult.CONTINUE;
                }
                throw exception;
            }

            private boolean isSystemDirectory(Path path) {
                return root.equals(path.getParent()) && WINDOWS_SYSTEM_DIRECTORIES.stream()
                        .anyMatch(name -> name.equalsIgnoreCase(path.getFileName().toString()));
            }

            @Override
            public FileVisitResult visitFile(Path path, BasicFileAttributes attributes) throws IOException {
                if (attributes.isRegularFile() && path.equals(path.toRealPath())) {
                    output.accept(readFile(root, path, attributes, contentRules));
                }
                return FileVisitResult.CONTINUE;
            }
        });
    }

    private ObjectMetadata readFile(Path root, Path path, BasicFileAttributes attributes, Map<UUID, String> contentRules) throws IOException {
        String name = path.getFileName().toString();
        int dot = name.lastIndexOf('.');
        String extension = dot > 0 && dot < name.length() - 1 ? name.substring(dot + 1) : "";
        String contentType = Files.probeContentType(path);
        var scanner = new DocumentScanner(extension, contentType, contentRules);
        var detector = piiProperties.enabled()
                ? new PiiDetector(piiProperties, extension, contentType) : null;
        try (var input = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
            var hashes = ContentHashes.read(input, attributes.size(), detector, piiTime, scanner);
            var pii = detector == null ? null : piiTime.record(detector::finish);
            String relative = root.relativize(path).toString().replace(path.getFileSystem().getSeparator(), "/");
            return new ObjectMetadata("file:///" + relative, extension, attributes.size(),
                    attributes.creationTime().toInstant(), attributes.lastModifiedTime().toInstant(),
                    attributes.lastAccessTime().toInstant(), null, null, hashes.sha256(), hashes.simhash(), null, pii, scanner.finish(null));
        }
    }

    private record Config(String directory) {
    }
}
