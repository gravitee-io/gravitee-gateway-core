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
package io.gravitee.rest.api.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.gravitee.rest.api.model.application.ApplicationSettings;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Nicolas GERAUD (nicolas.geraud at graviteesource.com)
 * @author GraviteeSource Team
 */
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@NoArgsConstructor
@AllArgsConstructor
@Builder
@JsonIgnoreProperties(ignoreUnknown = true)
public class UpdateApplicationEntity {

    @NotNull(message = "Application's name must not be null")
    @NotEmpty(message = "Application's name must not be empty")
    @Schema(description = "Application's name. Duplicate names can exists.", example = "My App")
    private String name;

    @NotNull(message = "Application's description must not be null")
    @Schema(
        description = "Application's description. A short description of your App.",
        example = "I can use a hundred characters to describe this App."
    )
    private String description;

    @Schema(description = "Domain used by the application, if relevant", example = "https://my-app.com")
    private String domain;

    private String picture;

    @JsonProperty("picture_url")
    private String pictureUrl;

    @NotNull(message = "Application's settings must not be null")
    private ApplicationSettings settings;

    @Schema(description = "Application groups. Used to add teams to your application.", example = "['MY_GROUP1', 'MY_GROUP2']")
    private Set<String> groups;

    /**
     * @deprecated Only for backward compatibility at the API level.
     *             Will be remove in a future version.
     */
    @Deprecated
    @Schema(description = "a string to describe the type of your app.", example = "iOS")
    private String type;

    /**
     * @deprecated Only for backward compatibility at the API level.
     *             Will be remove in a future version.
     */
    @Deprecated
    private String clientId;

    @JsonProperty("disable_membership_notifications")
    private boolean disableMembershipNotifications;

    @JsonProperty("api_key_mode")
    @Schema(description = "The API Key mode used for this application.")
    private ApiKeyMode apiKeyMode;

    private String background;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Set<String> getGroups() {
        return groups;
    }

    public void setGroups(Set<String> groups) {
        this.groups = groups;
    }

    public ApplicationSettings getSettings() {
        return settings;
    }

    public void setSettings(ApplicationSettings settings) {
        this.settings = settings;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getPicture() {
        return picture;
    }

    public void setPicture(String picture) {
        this.picture = picture;
    }

    public boolean isDisableMembershipNotifications() {
        return disableMembershipNotifications;
    }

    public void setDisableMembershipNotifications(boolean disableMembershipNotifications) {
        this.disableMembershipNotifications = disableMembershipNotifications;
    }

    public String getBackground() {
        return background;
    }

    public void setBackground(String background) {
        this.background = background;
    }

    public String getPictureUrl() {
        return pictureUrl;
    }

    public void setPictureUrl(String pictureUrl) {
        this.pictureUrl = pictureUrl;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public ApiKeyMode getApiKeyMode() {
        return apiKeyMode;
    }

    public void setApiKeyMode(ApiKeyMode apiKeyMode) {
        this.apiKeyMode = apiKeyMode;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("Application{");
        sb.append("description='").append(description).append('\'');
        sb.append(", name='").append(name).append('\'');
        sb.append(", groups='").append(groups).append('\'');
        sb.append(", disableMembershipNotifications='").append(disableMembershipNotifications);
        sb.append('}');
        return sb.toString();
    }
}
