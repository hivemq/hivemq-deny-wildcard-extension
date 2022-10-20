/*
 * Copyright 2018 dc-square GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.hivemq.extensions.wildcard.callbacks;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.SubscriptionAuthorizer;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.packets.subscribe.SubackReasonCode;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;


/**
 * DenyWildcard-Extension is an extension which denies a wildcard subscription
 * on top level for any Client. That means that you are not allowed to
 * subscribe for "#" only. Any sub level wildcard subscription like "/house/#"
 * is not affected and still possible.
 * Your Client disconnects after subscription on top level wildcard.
 *
 * @author Florian Limpoeck
 * @author Lukas Brandl
 */
public class DenyWildcardAuthorizer implements SubscriptionAuthorizer {

    public static final @NotNull DenyWildcardAuthorizer INSTANCE = new DenyWildcardAuthorizer();
    static final @NotNull String REASON_STRING = "Root wildcard subscriptions are not supported.";
    static final @NotNull String WILDCARD_CHARS = "#/+";
    private static final @NotNull Pattern SHARED_SUBSCRIPTION_PATTERN = Pattern.compile("\\$share(/.*?/(.*))");
    private static final @NotNull Logger LOG = LoggerFactory.getLogger(DenyWildcardAuthorizer.class);

    private DenyWildcardAuthorizer() {
    }

    @Override
    public void authorizeSubscribe(
            final @NotNull SubscriptionAuthorizerInput subscriptionAuthorizerInput,
            final @NotNull SubscriptionAuthorizerOutput subscriptionAuthorizerOutput) {
        final String topicFilter = subscriptionAuthorizerInput.getSubscription().getTopicFilter();

        if (topicFilter.startsWith("$share/")) {
            final Matcher matcher = SHARED_SUBSCRIPTION_PATTERN.matcher(topicFilter);
            if (matcher.matches()) {
                final String subscriptionTopic = matcher.group(2);
                if (StringUtils.containsOnly(subscriptionTopic, WILDCARD_CHARS)) {
                    LOG.debug("Client {} tried to subscribe to an denied shared root wildcard topic filter '{}'",
                            subscriptionAuthorizerInput.getClientInformation().getClientId(),
                            topicFilter);
                    subscriptionAuthorizerOutput.failAuthorization(SubackReasonCode.NOT_AUTHORIZED, REASON_STRING);
                    return;
                }
            }
        }

        if (topicFilter.startsWith("$expired/")) {
            final String expiredTopic = topicFilter.substring("$expired/".length());
            if (StringUtils.containsOnly(expiredTopic, WILDCARD_CHARS)) {
                subscriptionAuthorizerOutput.failAuthorization(SubackReasonCode.NOT_AUTHORIZED, REASON_STRING);
                return;
            }
        }

        if (topicFilter.startsWith("$dropped/")) {
            final String expiredTopic = topicFilter.substring("$dropped/".length());
            if (StringUtils.containsOnly(expiredTopic, WILDCARD_CHARS)) {
                subscriptionAuthorizerOutput.failAuthorization(SubackReasonCode.NOT_AUTHORIZED, REASON_STRING);
                return;
            }
        }

        if (StringUtils.containsOnly(topicFilter, WILDCARD_CHARS)) {
            LOG.debug("Client {} tried to subscribe to an denied root wildcard topic filter '{}'",
                    subscriptionAuthorizerInput.getClientInformation().getClientId(),
                    topicFilter);
            subscriptionAuthorizerOutput.failAuthorization(SubackReasonCode.NOT_AUTHORIZED, REASON_STRING);
        } else {
            subscriptionAuthorizerOutput.authorizeSuccessfully();
        }
    }
}
