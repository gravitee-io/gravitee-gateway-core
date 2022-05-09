/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.gateway.reactive.policy;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import io.gravitee.definition.model.flow.Flow;
import io.gravitee.definition.model.flow.Step;
import io.gravitee.gateway.policy.PolicyMetadata;
import io.gravitee.gateway.reactive.api.ExecutionPhase;
import io.gravitee.gateway.reactive.api.policy.Policy;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
@ExtendWith(MockitoExtension.class)
class DefaultPolicyChainFactoryTest {

    @Mock
    private PolicyManager policyManager;

    private DefaultPolicyChainFactory cut;

    @BeforeEach
    public void init() {
        cut = new DefaultPolicyChainFactory("unit-test", policyManager);
    }

    @Test
    public void shouldCreatePolicyChainForRequestPhase() {
        final Policy policy = mock(Policy.class);
        final Flow flow = mock(Flow.class);
        final Step step1 = mock(Step.class);
        final Step step2 = mock(Step.class);

        when(step1.isEnabled()).thenReturn(true);
        when(step2.isEnabled()).thenReturn(true);
        when(flow.getPre()).thenReturn(List.of(step1, step2));

        when(policyManager.create(eq(ExecutionPhase.REQUEST), any(PolicyMetadata.class))).thenReturn(policy);

        when(step1.getPolicy()).thenReturn("policy-step1");
        when(step1.getConfiguration()).thenReturn("config-step1");
        when(step1.getCondition()).thenReturn("condition-step1");

        when(step2.getPolicy()).thenReturn("policy-step2");
        when(step2.getConfiguration()).thenReturn("config-step2");
        when(step2.getCondition()).thenReturn("condition-step2");

        final PolicyChain policyChain = cut.create(flow, ExecutionPhase.REQUEST);
        assertNotNull(policyChain);

        verify(policyManager, times(1))
            .create(
                eq(ExecutionPhase.REQUEST),
                argThat(
                    metadata ->
                        metadata.getName().equals("policy-step1") &&
                        metadata.getConfiguration().equals("config-step1") &&
                        metadata.getCondition().equals("condition-step1")
                )
            );

        verify(policyManager, times(1))
            .create(
                eq(ExecutionPhase.REQUEST),
                argThat(
                    metadata ->
                        metadata.getName().equals("policy-step2") &&
                        metadata.getConfiguration().equals("config-step2") &&
                        metadata.getCondition().equals("condition-step2")
                )
            );

        verifyNoMoreInteractions(policyManager);
    }

    @Test
    public void shouldCreatePolicyChainWithoutDisabledSteps() {
        final Policy policy = mock(Policy.class);
        final Flow flow = mock(Flow.class);
        final Step step1 = mock(Step.class);
        final Step step2 = mock(Step.class);

        when(step1.isEnabled()).thenReturn(false);
        when(step2.isEnabled()).thenReturn(true);
        when(flow.getPre()).thenReturn(List.of(step1, step2));

        when(policyManager.create(eq(ExecutionPhase.REQUEST), any(PolicyMetadata.class))).thenReturn(policy);

        when(step2.getPolicy()).thenReturn("policy-step2");
        when(step2.getConfiguration()).thenReturn("config-step2");
        when(step2.getCondition()).thenReturn("condition-step2");

        final PolicyChain policyChain = cut.create(flow, ExecutionPhase.REQUEST);
        assertNotNull(policyChain);

        verify(policyManager, times(1))
            .create(
                eq(ExecutionPhase.REQUEST),
                argThat(
                    metadata ->
                        metadata.getName().equals("policy-step2") &&
                        metadata.getConfiguration().equals("config-step2") &&
                        metadata.getCondition().equals("condition-step2")
                )
            );

        verifyNoMoreInteractions(policyManager);
    }

    @Test
    public void shouldCreatePolicyChainOnceAndPutInCache() {
        final Policy policy = mock(Policy.class);
        final Flow flow = mock(Flow.class);
        final Step step1 = mock(Step.class);
        final Step step2 = mock(Step.class);

        when(step1.isEnabled()).thenReturn(true);
        when(step2.isEnabled()).thenReturn(true);
        when(flow.getPre()).thenReturn(List.of(step1, step2));

        when(policyManager.create(eq(ExecutionPhase.REQUEST), any(PolicyMetadata.class))).thenReturn(policy);

        when(step1.getPolicy()).thenReturn("policy-step1");
        when(step1.getConfiguration()).thenReturn("config-step1");
        when(step1.getCondition()).thenReturn("condition-step1");

        when(step2.getPolicy()).thenReturn("policy-step2");
        when(step2.getConfiguration()).thenReturn("config-step2");
        when(step2.getCondition()).thenReturn("condition-step2");

        for (int i = 0; i < 10; i++) {
            cut.create(flow, ExecutionPhase.REQUEST);
        }

        verify(policyManager, times(1))
            .create(
                eq(ExecutionPhase.REQUEST),
                argThat(
                    metadata ->
                        metadata.getName().equals("policy-step1") &&
                        metadata.getConfiguration().equals("config-step1") &&
                        metadata.getCondition().equals("condition-step1")
                )
            );

        verify(policyManager, times(1))
            .create(
                eq(ExecutionPhase.REQUEST),
                argThat(
                    metadata ->
                        metadata.getName().equals("policy-step2") &&
                        metadata.getConfiguration().equals("config-step2") &&
                        metadata.getCondition().equals("condition-step2")
                )
            );

        verifyNoMoreInteractions(policyManager);
    }

    @Test
    public void shouldCreatePolicyChainForResponsePhase() {
        final Policy policy = mock(Policy.class);
        final Flow flow = mock(Flow.class);
        final Step step1 = mock(Step.class);

        when(step1.isEnabled()).thenReturn(true);
        when(flow.getPost()).thenReturn(List.of(step1));

        when(policyManager.create(eq(ExecutionPhase.RESPONSE), any(PolicyMetadata.class))).thenReturn(policy);

        final PolicyChain policyChain = cut.create(flow, ExecutionPhase.RESPONSE);
        assertNotNull(policyChain);

        verify(policyManager, times(1)).create(eq(ExecutionPhase.RESPONSE), any(PolicyMetadata.class));
        verifyNoMoreInteractions(policyManager);
    }
}
