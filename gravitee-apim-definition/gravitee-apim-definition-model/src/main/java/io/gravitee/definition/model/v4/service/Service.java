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
package io.gravitee.definition.model.v4.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.databind.JsonNode;
import io.swagger.v3.oas.annotations.media.Schema;
import java.io.Serializable;
import javax.validation.constraints.NotBlank;
import lombok.*;

/**
 * @author Guillaume LAMIRAND (guillaume.lamirand at graviteesource.com)
 * @author GraviteeSource Team
 */
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
@Setter
@ToString
@EqualsAndHashCode
@Schema(name = "ServiceV4")
public class Service implements Serializable {

    private static final long serialVersionUID = 8224459863963093009L;

    @Builder.Default
    private boolean overrideConfiguration = false;

    @Builder.Default
    private boolean enabled = true;

    @JsonProperty(required = true)
    @NotBlank
    private String type;

    @Schema(implementation = Object.class)
    @JsonRawValue
    private Object configuration;

    @JsonSetter
    public void setConfiguration(final JsonNode configuration) {
        if (configuration != null) {
            this.configuration = configuration.toString();
        }
    }

    public void setConfiguration(final String configuration) {
        this.configuration = configuration;
    }

    public String getConfiguration() {
        return (String) configuration;
    }
}
