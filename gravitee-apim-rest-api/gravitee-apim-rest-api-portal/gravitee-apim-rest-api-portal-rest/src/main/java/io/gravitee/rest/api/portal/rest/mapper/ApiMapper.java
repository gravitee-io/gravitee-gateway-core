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
package io.gravitee.rest.api.portal.rest.mapper;

import io.gravitee.common.component.Lifecycle;
import io.gravitee.rest.api.model.PrimaryOwnerEntity;
import io.gravitee.rest.api.model.RatingSummaryEntity;
import io.gravitee.rest.api.model.Visibility;
import io.gravitee.rest.api.model.api.ApiEntity;
import io.gravitee.rest.api.model.api.ApiEntrypointEntity;
import io.gravitee.rest.api.model.api.ApiLifecycleState;
import io.gravitee.rest.api.model.parameters.Key;
import io.gravitee.rest.api.model.parameters.ParameterReferenceType;
import io.gravitee.rest.api.portal.rest.model.Api;
import io.gravitee.rest.api.portal.rest.model.ApiLinks;
import io.gravitee.rest.api.portal.rest.model.RatingSummary;
import io.gravitee.rest.api.portal.rest.model.User;
import io.gravitee.rest.api.service.CategoryService;
import io.gravitee.rest.api.service.ParameterService;
import io.gravitee.rest.api.service.RatingService;
import io.gravitee.rest.api.service.common.ExecutionContext;
import io.gravitee.rest.api.service.common.GraviteeContext;
import io.gravitee.rest.api.service.exceptions.CategoryNotFoundException;
import java.math.BigDecimal;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * @author Florent CHAMFROY (florent.chamfroy at graviteesource.com)
 * @author GraviteeSource Team
 */
@Component
public class ApiMapper {

    @Autowired
    private RatingService ratingService;

    @Autowired
    private CategoryService categoryService;

    @Autowired
    private ParameterService parameterService;

    public Api convert(ExecutionContext executionContext, ApiEntity api) {
        final Api apiItem = new Api();
        apiItem.setDescription(api.getDescription());

        List<ApiEntrypointEntity> apiEntrypoints = api.getEntrypoints();
        if (apiEntrypoints != null) {
            List<String> entrypoints = apiEntrypoints.stream().map(ApiEntrypointEntity::getTarget).collect(Collectors.toList());
            apiItem.setEntrypoints(entrypoints);
        }

        apiItem.setDraft(api.getLifecycleState() == ApiLifecycleState.UNPUBLISHED || api.getLifecycleState() == ApiLifecycleState.CREATED);
        apiItem.setRunning(api.getState() == Lifecycle.State.STARTED);
        apiItem.setPublic(api.getVisibility() == Visibility.PUBLIC);
        apiItem.setId(api.getId());

        List<String> apiLabels = api.getLabels();
        if (apiLabels != null) {
            apiItem.setLabels(new ArrayList<>(apiLabels));
        } else {
            apiItem.setLabels(new ArrayList<>());
        }

        apiItem.setName(api.getName());

        PrimaryOwnerEntity primaryOwner = api.getPrimaryOwner();
        if (primaryOwner != null) {
            User owner = new User();
            owner.setId(primaryOwner.getId());
            owner.setDisplayName(primaryOwner.getDisplayName());
            owner.setEmail(primaryOwner.getEmail());
            apiItem.setOwner(owner);
        }
        apiItem.setPages(null);
        apiItem.setPlans(null);

        if (ratingService.isEnabled(executionContext)) {
            final RatingSummaryEntity ratingSummaryEntity = ratingService.findSummaryByApi(executionContext, api.getId());
            RatingSummary ratingSummary = new RatingSummary()
                .average(ratingSummaryEntity.getAverageRate())
                .count(BigDecimal.valueOf(ratingSummaryEntity.getNumberOfRatings()));
            apiItem.setRatingSummary(ratingSummary);
        }

        if (api.getCreatedAt() != null) {
            apiItem.setCreatedAt(api.getCreatedAt().toInstant().atOffset(ZoneOffset.UTC));
        }
        if (api.getUpdatedAt() != null) {
            apiItem.setUpdatedAt(api.getUpdatedAt().toInstant().atOffset(ZoneOffset.UTC));
        }

        apiItem.setVersion(api.getVersion());

        boolean isCategoryModeEnabled =
            this.parameterService.findAsBoolean(executionContext, Key.PORTAL_APIS_CATEGORY_ENABLED, ParameterReferenceType.ENVIRONMENT);
        if (isCategoryModeEnabled && api.getCategories() != null) {
            apiItem.setCategories(
                api
                    .getCategories()
                    .stream()
                    .filter(
                        categoryId -> {
                            try {
                                categoryService.findNotHiddenById(categoryId, executionContext.getEnvironmentId());
                                return true;
                            } catch (CategoryNotFoundException v) {
                                return false;
                            }
                        }
                    )
                    .collect(Collectors.toList())
            );
        } else {
            apiItem.setCategories(new ArrayList<>());
        }

        return apiItem;
    }

    public ApiLinks computeApiLinks(String basePath, Date updateDate) {
        ApiLinks apiLinks = new ApiLinks();
        apiLinks.setLinks(basePath + "/links");
        apiLinks.setMetrics(basePath + "/metrics");
        apiLinks.setPages(basePath + "/pages");
        apiLinks.setPlans(basePath + "/plans");
        apiLinks.setRatings(basePath + "/ratings");
        apiLinks.setSelf(basePath);
        final String hash = updateDate == null ? "" : String.valueOf(updateDate.getTime());
        apiLinks.setPicture(basePath + "/picture?" + hash);
        apiLinks.setBackground(basePath + "/background?" + hash);
        return apiLinks;
    }
}
