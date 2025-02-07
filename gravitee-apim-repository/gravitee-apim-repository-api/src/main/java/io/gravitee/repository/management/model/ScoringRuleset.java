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
package io.gravitee.repository.management.model;

import java.util.Date;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@NoArgsConstructor
@AllArgsConstructor
@Builder(toBuilder = true)
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@Getter
@Setter
@ToString
public final class ScoringRuleset {

    @EqualsAndHashCode.Include
    private String id;

    private String name;
    private String description;
    private Format format;
    private String referenceId;
    private String referenceType;
    private Date createdAt;
    private Date updatedAt;
    private String payload;

    public enum Format {
        GRAVITEE_FEDERATION,
        GRAVITEE_MESSAGE,
        GRAVITEE_PROXY,
        GRAVITEE_NATIVE,
        OPENAPI,
        ASYNCAPI,
    }
}
