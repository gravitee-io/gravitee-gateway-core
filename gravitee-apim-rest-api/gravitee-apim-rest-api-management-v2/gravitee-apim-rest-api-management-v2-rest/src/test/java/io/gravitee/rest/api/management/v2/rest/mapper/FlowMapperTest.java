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
package io.gravitee.rest.api.management.v2.rest.mapper;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.fasterxml.jackson.core.JsonProcessingException;
import fixtures.FlowFixtures;
import io.gravitee.definition.jackson.datatype.GraviteeMapper;
import io.gravitee.definition.model.v4.flow.Flow;
import io.gravitee.definition.model.v4.flow.selector.ChannelSelector;
import io.gravitee.definition.model.v4.flow.step.Step;
import io.gravitee.rest.api.management.v2.rest.model.FlowV2;
import io.gravitee.rest.api.management.v2.rest.model.FlowV4;
import io.gravitee.rest.api.management.v2.rest.model.StepV2;
import io.gravitee.rest.api.management.v2.rest.model.StepV4;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;

public class FlowMapperTest {

    private final FlowMapper flowMapper = Mappers.getMapper(FlowMapper.class);

    @Test
    void shouldMapFromFlowEntityV4() throws JsonProcessingException {
        var flowEntityV4 = FlowFixtures.aModelFlowV4();
        var flowV4 = flowMapper.map(flowEntityV4);
        assertThat(flowV4).isNotNull();
        assertFlowV4Equals(flowEntityV4, flowV4);
    }

    @Test
    void shouldMapToFlowEntityV4() throws JsonProcessingException {
        var flowV4 = FlowFixtures.aFlowV4();
        var flowEntityV4 = flowMapper.map(flowV4);
        assertThat(flowV4).isNotNull();
        assertFlowV4Equals(flowEntityV4, flowV4);
    }

    private void assertFlowV4Equals(Flow flowEntityV4, FlowV4 flowV4) throws JsonProcessingException {
        assertEquals(flowEntityV4.getName(), flowV4.getName());

        final var flowSelectors = flowEntityV4.getSelectors();
        final var flowV4Selectors = flowV4.getSelectors();

        assertFalse(flowSelectors.isEmpty());
        assertEquals(flowSelectors.size(), flowV4Selectors.size());

        for (int j = 0; j < flowSelectors.size(); j++) {
            final ChannelSelector selector = (ChannelSelector) flowSelectors.get(0);
            final io.gravitee.rest.api.management.v2.rest.model.ChannelSelector selectorV4 = flowV4Selectors.get(0).getChannelSelector();

            assertEquals(selector.getChannel(), selectorV4.getChannel());
            assertEquals(selector.getChannelOperator().name(), selectorV4.getChannelOperator().name());
            assertEquals(selector.getEntrypoints(), selectorV4.getEntrypoints());
            assertEquals(selector.getType().name(), selectorV4.getType().name());

            assertEquals(
                selector.getOperations().stream().map(Enum::name).collect(Collectors.toSet()),
                selectorV4.getOperations().stream().map(Enum::name).collect(Collectors.toSet())
            );
        }

        assertStepsV4Equals(flowEntityV4.getRequest(), flowV4.getRequest());
        assertStepsV4Equals(flowEntityV4.getPublish(), flowV4.getPublish());
        assertStepsV4Equals(flowEntityV4.getResponse(), flowV4.getResponse());
        assertStepsV4Equals(flowEntityV4.getSubscribe(), flowV4.getSubscribe());
    }

    private void assertStepsV4Equals(List<Step> steps, List<StepV4> stepsV4) throws JsonProcessingException {
        assertEquals(steps.size(), steps.size());

        for (int i = 0; i < steps.size(); i++) {
            final var step = steps.get(i);
            final var stepV4 = stepsV4.get(i);
            assertEquals(step.getName(), stepV4.getName());
            assertEquals(step.getDescription(), stepV4.getDescription());
            assertEquals(step.getPolicy(), stepV4.getPolicy());
            assertEquals(step.getCondition(), stepV4.getCondition());
            assertEquals(step.getMessageCondition(), stepV4.getMessageCondition());
            assertEquals(step.getConfiguration(), new GraviteeMapper().writeValueAsString(stepV4.getConfiguration()));
        }
    }

    @Test
    void shouldMapFromFlowEntityV2() throws JsonProcessingException {
        var flowEntityV2 = FlowFixtures.aModelFlowV2();
        var flowV2 = flowMapper.map(flowEntityV2);
        assertThat(flowV2).isNotNull();
        assertFlowV2Equals(flowEntityV2, flowV2);
    }

    @Test
    void shouldMapToFlowEntityV2() throws JsonProcessingException {
        var flowV2 = FlowFixtures.aFlowV2();
        var flowEntityV2 = flowMapper.map(flowV2);
        assertThat(flowV2).isNotNull();
        assertFlowV2Equals(flowEntityV2, flowV2);
    }

    private void assertFlowV2Equals(io.gravitee.definition.model.flow.Flow flowEntityV2, FlowV2 flowV2) throws JsonProcessingException {
        assertEquals(flowEntityV2.getName(), flowV2.getName());
        assertEquals(flowEntityV2.getPath(), flowV2.getPathOperator().getPath());
        assertEquals(flowEntityV2.getOperator().name(), flowV2.getPathOperator().getOperator().name());
        assertEquals(flowEntityV2.getCondition(), flowV2.getCondition());
        assertStepsV2Equals(flowEntityV2.getPre(), flowV2.getPre());
        assertStepsV2Equals(flowEntityV2.getPost(), flowV2.getPost());
    }

    private void assertStepsV2Equals(List<io.gravitee.definition.model.flow.Step> steps, List<StepV2> stepsV2)
        throws JsonProcessingException {
        assertEquals(steps.size(), steps.size());

        for (int i = 0; i < steps.size(); i++) {
            final var step = steps.get(i);
            final var stepV2 = stepsV2.get(i);
            assertEquals(step.getName(), stepV2.getName());
            assertEquals(step.getDescription(), stepV2.getDescription());
            assertEquals(step.getPolicy(), stepV2.getPolicy());
            assertEquals(step.getCondition(), stepV2.getCondition());
            assertEquals(step.getConfiguration(), new GraviteeMapper().writeValueAsString(stepV2.getConfiguration()));
        }
    }
}
