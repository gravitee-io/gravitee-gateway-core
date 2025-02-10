/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
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
package io.gravitee.apim.infra.adapter;

import io.gravitee.apim.core.scoring.model.ScoringRuleset;
import jakarta.annotation.Nullable;
import org.mapstruct.Mapper;
import org.mapstruct.factory.Mappers;

@Mapper
public interface ScoringRulesetAdapter {
    ScoringRulesetAdapter INSTANCE = Mappers.getMapper(ScoringRulesetAdapter.class);

    ScoringRuleset toEntity(io.gravitee.repository.management.model.ScoringRuleset source);
    io.gravitee.repository.management.model.ScoringRuleset toRepository(ScoringRuleset source);

    /**
     * This method is explicit to show at compile time the link between
     * <ul>
     *     <li>{@link io.gravitee.apim.core.scoring.model.ScoringRuleset.Format}</li>
     *     <li>{@link io.gravitee.repository.management.model.ScoringRuleset.Format}</li>
     * </ul>
     */
    @Nullable
    default ScoringRuleset.Format map(io.gravitee.repository.management.model.ScoringRuleset.Format source) {
        return switch (source) {
            case GRAVITEE_NATIVE -> ScoringRuleset.Format.GRAVITEE_NATIVE;
            case OPENAPI -> ScoringRuleset.Format.OPENAPI;
            case ASYNCAPI -> ScoringRuleset.Format.ASYNCAPI;
            case GRAVITEE_PROXY -> ScoringRuleset.Format.GRAVITEE_PROXY;
            case GRAVITEE_MESSAGE -> ScoringRuleset.Format.GRAVITEE_MESSAGE;
            case GRAVITEE_FEDERATION -> ScoringRuleset.Format.GRAVITEE_FEDERATION;
            case null -> null;
        };
    }

    /**
     * This method is explicit to show at compile time the link between
     * <ul>
     *     <li>{@link io.gravitee.apim.core.scoring.model.ScoringRuleset.Format}</li>
     *     <li>{@link io.gravitee.repository.management.model.ScoringRuleset.Format}</li>
     * </ul>
     */
    @Nullable
    default io.gravitee.repository.management.model.ScoringRuleset.Format map(ScoringRuleset.Format source) {
        return switch (source) {
            case OPENAPI -> io.gravitee.repository.management.model.ScoringRuleset.Format.OPENAPI;
            case ASYNCAPI -> io.gravitee.repository.management.model.ScoringRuleset.Format.ASYNCAPI;
            case GRAVITEE_PROXY -> io.gravitee.repository.management.model.ScoringRuleset.Format.GRAVITEE_PROXY;
            case GRAVITEE_MESSAGE -> io.gravitee.repository.management.model.ScoringRuleset.Format.GRAVITEE_MESSAGE;
            case GRAVITEE_FEDERATION -> io.gravitee.repository.management.model.ScoringRuleset.Format.GRAVITEE_FEDERATION;
            case GRAVITEE_NATIVE -> io.gravitee.repository.management.model.ScoringRuleset.Format.GRAVITEE_NATIVE;
            case null -> null;
        };
    }
}
