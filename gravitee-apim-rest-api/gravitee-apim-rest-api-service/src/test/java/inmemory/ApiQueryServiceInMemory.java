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
package inmemory;

import io.gravitee.apim.core.api.model.Api;
import io.gravitee.apim.core.api.model.ApiFieldFilter;
import io.gravitee.apim.core.api.model.ApiSearchCriteria;
import io.gravitee.apim.core.api.model.Sortable;
import io.gravitee.apim.core.api.query_service.ApiQueryService;
import io.gravitee.common.data.domain.Page;
import io.gravitee.rest.api.model.common.Pageable;
import io.gravitee.rest.api.model.context.IntegrationContext;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

public class ApiQueryServiceInMemory implements ApiQueryService, InMemoryAlternative<Api> {

    private final List<Api> storage;

    public ApiQueryServiceInMemory() {
        storage = new ArrayList<>();
    }

    public ApiQueryServiceInMemory(ApiCrudServiceInMemory apiCrudServiceInMemory) {
        storage = apiCrudServiceInMemory.storage;
    }

    /**
     * WARNING: this implementation doesn't actually filter the API present in the storage. Instead, it will return all applications from storage.
     * Except for the integrationId where filtering is implemented.
     */
    @Override
    public Stream<Api> search(ApiSearchCriteria apiCriteria, Sortable sortable, ApiFieldFilter apiFieldFilter) {
        if (apiCriteria != null && (apiCriteria.getIntegrationId() != null || apiCriteria.getIds() != null)) {
            return this.storage()
                .stream()
                .filter(api -> {
                    var matchesIntegrationId =
                        Objects.isNull(apiCriteria.getIntegrationId()) ||
                        Objects.equals(((IntegrationContext) api.getOriginContext()).getIntegrationId(), apiCriteria.getIntegrationId());
                    var matchesApiId = Objects.isNull(apiCriteria.getIds()) || apiCriteria.getIds().contains(api.getId());
                    return matchesIntegrationId && matchesApiId;
                });
        }
        return this.storage().stream();
    }

    @Override
    public Optional<Api> findByEnvironmentIdAndCrossId(String environmentId, String crossId) {
        return storage.stream().filter(api -> api.getEnvironmentId().equals(environmentId) && api.getCrossId().equals(crossId)).findFirst();
    }

    @Override
    public Page<Api> findByIntegrationId(String integrationId, Pageable pageable) {
        var pageNumber = pageable.getPageNumber();
        var pageSize = pageable.getPageSize();

        var matches = storage
            .stream()
            .filter(api -> {
                var integrationContext = (IntegrationContext) api.getOriginContext();
                var originIntegrationId = integrationContext.getIntegrationId();
                return originIntegrationId.equals(integrationId);
            })
            .sorted(Comparator.comparing(Api::getUpdatedAt).reversed())
            .toList();

        var page = matches.size() <= pageSize
            ? matches
            : matches.subList((pageNumber - 1) * pageSize, Math.min(pageNumber * pageSize, matches.size()));

        return new Page<>(page, pageNumber, pageSize, matches.size());
    }

    @Override
    public void initWith(List<Api> items) {
        storage.addAll(items);
    }

    @Override
    public void reset() {
        storage.clear();
    }

    @Override
    public List<Api> storage() {
        return Collections.unmodifiableList(storage);
    }
}
