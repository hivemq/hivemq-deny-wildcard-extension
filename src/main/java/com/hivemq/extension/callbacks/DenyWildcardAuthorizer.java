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

package com.hivemq.extension.callbacks;

import com.hivemq.extension.sdk.api.annotations.NotNull;
import com.hivemq.extension.sdk.api.auth.SubscriptionAuthorizer;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.packets.subscribe.SubackReasonCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * DenyWildcard-Extension is a extension which denies a wildcard subscription
 * on top level for any Client. That means that you are not allowed to
 * subscribe for "#" only. Any sub level wildcard subscription like "/house/#"
 * is not affected and still possible.
 * Your Client disconnects after subscription on top level wildcard.
 *
 * @author Florian Limpoeck
 * @author Lukas Brandl
 */
public class DenyWildcardAuthorizer implements SubscriptionAuthorizer {

    public static final DenyWildcardAuthorizer INSTANCE = new DenyWildcardAuthorizer();
    public static final String REASON_STRING = "Root wildcard subscription not supported.";

    private DenyWildcardAuthorizer() {
    }

    public static final String WILDCARD = "#";
    private static Logger logger = LoggerFactory.getLogger(DenyWildcardAuthorizer.class);

    @Override
    public void authorizeSubscribe(@NotNull final SubscriptionAuthorizerInput subscriptionAuthorizerInput, @NotNull final SubscriptionAuthorizerOutput subscriptionAuthorizerOutput) {
        final String topicFilter = subscriptionAuthorizerInput.getSubscription().getTopicFilter();
        if (topicFilter.equals(WILDCARD)) {
            logger.debug("Client {} tried to subscribe to an invalid subscription '#'", subscriptionAuthorizerInput.getClientInformation().getClientId());
            subscriptionAuthorizerOutput.failAuthorization(SubackReasonCode.NOT_AUTHORIZED, REASON_STRING);
        } else {
            subscriptionAuthorizerOutput.authorizeSuccessfully();
        }
    }
}
