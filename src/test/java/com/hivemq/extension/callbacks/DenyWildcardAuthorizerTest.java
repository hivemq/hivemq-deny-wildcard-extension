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

import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerInput;
import com.hivemq.extension.sdk.api.auth.parameter.SubscriptionAuthorizerOutput;
import com.hivemq.extension.sdk.api.client.parameter.ClientInformation;
import com.hivemq.extension.sdk.api.packets.subscribe.SubackReasonCode;
import com.hivemq.extension.sdk.api.packets.subscribe.Subscription;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * @author Florian Limpoeck
 */
public class DenyWildcardAuthorizerTest {

    @Mock
    SubscriptionAuthorizerInput input;

    @Mock
    SubscriptionAuthorizerOutput output;

    @Mock
    ClientInformation clientInformation;

    @Mock
    Subscription subscription;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        when(input.getClientInformation()).thenReturn(clientInformation);
        when(clientInformation.getClientId()).thenReturn("client");
        when(input.getSubscription()).thenReturn(subscription);
    }

    @Test
    public void test_denied_hashtag() {
        when(input.getSubscription().getTopicFilter()).thenReturn("#");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).failAuthorization(SubackReasonCode.NOT_AUTHORIZED, DenyWildcardAuthorizer.REASON_STRING);
    }

    @Test
    public void test_denied_plus() {
        when(input.getSubscription().getTopicFilter()).thenReturn("+");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).failAuthorization(SubackReasonCode.NOT_AUTHORIZED, DenyWildcardAuthorizer.REASON_STRING);
    }

    @Test
    public void test_denied_plus_slash() {
        when(input.getSubscription().getTopicFilter()).thenReturn("+/");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).failAuthorization(SubackReasonCode.NOT_AUTHORIZED, DenyWildcardAuthorizer.REASON_STRING);
    }

    @Test
    public void test_denied_hashtag_slash() {
        when(input.getSubscription().getTopicFilter()).thenReturn("#/");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).failAuthorization(SubackReasonCode.NOT_AUTHORIZED, DenyWildcardAuthorizer.REASON_STRING);
    }

    @Test
    public void test_denied_hashtag_plus() {
        when(input.getSubscription().getTopicFilter()).thenReturn("#/+");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).failAuthorization(SubackReasonCode.NOT_AUTHORIZED, DenyWildcardAuthorizer.REASON_STRING);
    }

    @Test
    public void test_denied_plus_hashtag() {
        when(input.getSubscription().getTopicFilter()).thenReturn("+/#");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).failAuthorization(SubackReasonCode.NOT_AUTHORIZED, DenyWildcardAuthorizer.REASON_STRING);
    }

    @Test
    public void test_denied_slash_plus() {
        when(input.getSubscription().getTopicFilter()).thenReturn("/+");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).failAuthorization(SubackReasonCode.NOT_AUTHORIZED, DenyWildcardAuthorizer.REASON_STRING);
    }

    @Test
    public void test_denied_slash_hashtag() {
        when(input.getSubscription().getTopicFilter()).thenReturn("/#");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).failAuthorization(SubackReasonCode.NOT_AUTHORIZED, DenyWildcardAuthorizer.REASON_STRING);
    }

    @Test
    public void test_success() {
        when(input.getSubscription().getTopicFilter()).thenReturn("topic");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).authorizeSuccessfully();
    }

    @Test
    public void test_success_non_root_hashtag() {
        when(input.getSubscription().getTopicFilter()).thenReturn("topic/#");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).authorizeSuccessfully();
    }

    @Test
    public void test_success_non_root_plus() {
        when(input.getSubscription().getTopicFilter()).thenReturn("topic/+");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).authorizeSuccessfully();
    }

    @Test
    public void test_success_non_trailing_plus() {
        when(input.getSubscription().getTopicFilter()).thenReturn("+/topic");
        DenyWildcardAuthorizer.INSTANCE.authorizeSubscribe(input, output);

        verify(output).authorizeSuccessfully();
    }

}
