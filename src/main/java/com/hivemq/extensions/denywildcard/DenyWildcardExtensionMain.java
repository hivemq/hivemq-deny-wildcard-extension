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

import com.hivemq.extension.sdk.api.ExtensionMain;
import com.hivemq.extension.sdk.api.parameter.ExtensionStartInput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStartOutput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStopInput;
import com.hivemq.extension.sdk.api.parameter.ExtensionStopOutput;
import com.hivemq.extension.sdk.api.services.Services;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Set;

/**
 * @author Lukas Brandl
 */
@SuppressWarnings("unused")
public class DenyWildcardExtensionMain implements ExtensionMain {

    private static final @NotNull Logger LOG = LoggerFactory.getLogger(DenyWildcardExtensionMain.class);

    @Override
    public void extensionStart(
            final @NotNull ExtensionStartInput extensionStartInput,
            final @NotNull ExtensionStartOutput extensionStartOutput) {
        final Set<String> allowedClientIds;
        try {
            allowedClientIds = DenyWildcardConfig.readAllowedClientIds(
                    extensionStartInput.getExtensionInformation().getExtensionHomeFolder().toPath());
        } catch (final IOException e) {
            LOG.error("Could not read {} of the Deny Wildcard extension.", DenyWildcardConfig.CONFIG_FILE, e);
            extensionStartOutput.preventExtensionStartup("Could not read " + DenyWildcardConfig.CONFIG_FILE);
            return;
        }
        LOG.info("Using the Deny Wildcard extension. Subscribing to '#' is prohibited for all but {} allowed clients.",
                allowedClientIds.size());
        final var authorizer = new DenyWildcardAuthorizer(allowedClientIds);
        Services.securityRegistry().setAuthorizerProvider(authorizerProviderInput -> authorizer);
    }

    @Override
    public void extensionStop(
            final @NotNull ExtensionStopInput extensionStopInput,
            final @NotNull ExtensionStopOutput extensionStopOutput) {
    }
}
