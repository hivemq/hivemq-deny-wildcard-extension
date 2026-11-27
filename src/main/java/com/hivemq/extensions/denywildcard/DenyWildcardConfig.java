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

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Reads the optional {@code conf/config.properties} in the extension home folder. A missing file means no client is
 * allowed to subscribe to a root wildcard.
 */
final class DenyWildcardConfig {

    static final @NotNull String CONFIG_FILE = "conf/config.properties";
    static final @NotNull String ALLOWED_CLIENT_IDS = "allowed-client-ids";

    private DenyWildcardConfig() {
    }

    static @NotNull Set<String> readAllowedClientIds(final @NotNull Path extensionHome) throws IOException {
        final var configFile = extensionHome.resolve(CONFIG_FILE);
        if (!Files.exists(configFile)) {
            return Set.of();
        }
        final var properties = new Properties();
        try (final Reader reader = Files.newBufferedReader(configFile, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return Arrays.stream(properties.getProperty(ALLOWED_CLIENT_IDS, "").split(","))
                .map(String::trim)
                .filter(clientId -> !clientId.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }
}
