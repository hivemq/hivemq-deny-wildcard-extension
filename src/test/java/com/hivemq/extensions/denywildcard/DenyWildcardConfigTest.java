/*
 * Copyright 2019-present HiveMQ GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hivemq.extensions.denywildcard;

import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DenyWildcardConfigTest {

    @TempDir
    @NotNull Path extensionHome;

    @Test
    void test_missing_file_allows_nobody() throws Exception {
        assertEquals(Set.of(), DenyWildcardConfig.readAllowedClientIds(extensionHome));
    }

    @Test
    void test_missing_property_allows_nobody() throws Exception {
        writeConfig("other=value\n");
        assertEquals(Set.of(), DenyWildcardConfig.readAllowedClientIds(extensionHome));
    }

    @Test
    void test_reads_trimmed_client_ids_and_skips_empty_entries() throws Exception {
        writeConfig("allowed-client-ids = client-a, client-b ,,\n");
        assertEquals(Set.of("client-a", "client-b"), DenyWildcardConfig.readAllowedClientIds(extensionHome));
    }

    private void writeConfig(final @NotNull String content) throws Exception {
        final var configFile = extensionHome.resolve(DenyWildcardConfig.CONFIG_FILE);
        Files.createDirectories(configFile.getParent());
        Files.writeString(configFile, content);
    }
}
