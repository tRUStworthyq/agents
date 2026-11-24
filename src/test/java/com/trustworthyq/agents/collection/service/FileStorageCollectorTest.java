package com.trustworthyq.agents.collection.service;

import com.trustworthyq.agents.collection.dto.ObjectMetadata;
import com.trustworthyq.agents.collection.exception.CollectionException;
import com.trustworthyq.agents.pii.config.PiiProperties;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FileStorageCollectorTest {
    @TempDir
    Path root;

    @Test
    void collectsNestedFilesWithHashesAndPii() throws IOException {
        Files.createDirectories(root.resolve("reports/nested"));
        Files.writeString(root.resolve("reports/nested/contact.txt"), "Contact: person@example.org");
        Files.writeString(root.resolve("outside.txt"), "outside");
        var files = new ArrayList<ObjectMetadata>();

        collector().collect("{\"directory\":\"reports\"}", files::add);

        assertThat(files).singleElement().satisfies(file -> {
            assertThat(file.path()).isEqualTo("file:///reports/nested/contact.txt");
            assertThat(file.sizeBytes()).isEqualTo(27);
            assertThat(file.sha256()).matches("[0-9a-f]{64}");
            assertThat(file.simhash()).matches("[0-9a-f]{16}");
            assertThat(file.pii().toString()).contains("DETECTED", "EMAIL");
        });
    }

    @Test
    void rejectsDirectoriesOutsideRoot() {
        assertThatThrownBy(() -> collector().collect("{\"directory\":\"..\"}", file -> {}))
                .isInstanceOf(CollectionException.class)
                .hasMessage("FILESYSTEM_INVALID_DIRECTORY");
    }

    @Test
    void rejectsHostDriveInConnectionSettings() {
        assertThatThrownBy(() -> collector().collect("{\"directory\":\"G:/\"}", file -> {}))
                .isInstanceOf(CollectionException.class)
                .hasMessage("FILESYSTEM_INVALID_DIRECTORY");
    }

    @Test
    void skipsWindowsSystemDirectoriesAtMountedRoot() throws IOException {
        for (String directory : Set.of("$Recycle.Bin", "System Volume Information")) {
            Files.createDirectory(root.resolve(directory));
            Files.writeString(root.resolve(directory).resolve("fixture.txt"), "ignored");
        }
        Files.writeString(root.resolve("document.txt"), "fixture");
        var files = new ArrayList<ObjectMetadata>();

        collector().collect("{\"directory\":\".\"}", files::add);

        assertThat(files).extracting(ObjectMetadata::path).containsExactly("file:///document.txt");
    }

    private FileStorageCollector collector() {
        return new FileStorageCollector(new JsonMapper(), root.toString(),
                new PiiProperties(true, 256, 4096, Set.of("EMAIL")), new SimpleMeterRegistry());
    }
}
