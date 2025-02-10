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
package io.gravitee.apim.core.scoring.model;

import java.time.ZonedDateTime;
import lombok.Builder;
import lombok.With;

@Builder(toBuilder = true)
public record ScoringRuleset(
    String id,
    String name,
    String description,
    Format format,
    @With String referenceId,
    ReferenceType referenceType,
    String payload,
    ZonedDateTime createdAt,
    ZonedDateTime updatedAt
) {
    public enum ReferenceType {
        ENVIRONMENT,
    }

    public enum Format {
        GRAVITEE_FEDERATION,
        GRAVITEE_MESSAGE,
        GRAVITEE_PROXY,
        GRAVITEE_NATIVE,
        OPENAPI,
        ASYNCAPI,
    }
}
