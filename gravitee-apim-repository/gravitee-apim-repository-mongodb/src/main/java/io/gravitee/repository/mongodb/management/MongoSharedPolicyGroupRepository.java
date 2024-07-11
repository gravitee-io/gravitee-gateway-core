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
package io.gravitee.repository.mongodb.management;

import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.SharedPolicyGroupRepository;
import io.gravitee.repository.management.model.SharedPolicyGroup;
import io.gravitee.repository.mongodb.management.internal.model.SharedPolicyGroupMongo;
import io.gravitee.repository.mongodb.management.internal.sharedpolicygroups.SharedPolicyGroupMongoRepository;
import io.gravitee.repository.mongodb.management.mapper.GraviteeMapper;
import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class MongoSharedPolicyGroupRepository implements SharedPolicyGroupRepository {

    private final Logger LOGGER = LoggerFactory.getLogger(MongoSharedPolicyGroupRepository.class);

    private final GraviteeMapper mapper;

    private final SharedPolicyGroupMongoRepository internalSharedPolicyGroupMongoRepo;

    @Override
    public Optional<SharedPolicyGroup> findById(String s) throws TechnicalException {
        LOGGER.debug("Find shared policy group by ID [{}]", s);

        final SharedPolicyGroupMongo sharedPolicyGroupMongo = internalSharedPolicyGroupMongoRepo.findById(s).orElse(null);

        LOGGER.debug("Find shared policy group by ID [{}] - Done", sharedPolicyGroupMongo);

        return Optional.ofNullable(mapSharedPolicyGroup(sharedPolicyGroupMongo));
    }

    @Override
    public SharedPolicyGroup create(SharedPolicyGroup item) throws TechnicalException {
        LOGGER.debug("Create shared policy group with id [{}]", item.getId());

        SharedPolicyGroupMongo sharedPolicyGroupMongo = mapSharedPolicyGroup(item);

        SharedPolicyGroupMongo created = internalSharedPolicyGroupMongoRepo.insert(sharedPolicyGroupMongo);

        SharedPolicyGroup res = mapSharedPolicyGroup(created);

        LOGGER.debug("Create shared policy group with id [{}] - Done", res.getId());
        return res;
    }

    @Override
    public SharedPolicyGroup update(SharedPolicyGroup item) throws TechnicalException {
        if (item == null || item.getId() == null) {
            throw new IllegalStateException("Shared policy group to update must have an id");
        }

        SharedPolicyGroupMongo sharedPolicyGroupMongo = internalSharedPolicyGroupMongoRepo.findById(item.getId()).orElse(null);

        if (sharedPolicyGroupMongo == null) {
            throw new IllegalStateException(String.format("No shared policy group found with id [%s]", item.getId()));
        }

        LOGGER.debug("Update shared policy group with id [{}]", item.getId());
        sharedPolicyGroupMongo = mapSharedPolicyGroup(item);
        sharedPolicyGroupMongo = internalSharedPolicyGroupMongoRepo.save(sharedPolicyGroupMongo);
        LOGGER.debug("Update shared policy group with id [{}] - Done", item.getId());
        return mapSharedPolicyGroup(sharedPolicyGroupMongo);
    }

    @Override
    public void delete(String id) throws TechnicalException {
        try {
            internalSharedPolicyGroupMongoRepo.deleteById(id);
        } catch (Exception e) {
            LOGGER.error("An error occurred when deleting shared policy group [{}]", id, e);
            throw new TechnicalException("An error occurred when deleting shared policy group");
        }
    }

    @Override
    public Set<SharedPolicyGroup> findAll() throws TechnicalException {
        throw new IllegalStateException("Not implemented");
    }

    private SharedPolicyGroup mapSharedPolicyGroup(SharedPolicyGroupMongo item) {
        return item == null ? null : mapper.map(item);
    }

    private SharedPolicyGroupMongo mapSharedPolicyGroup(SharedPolicyGroup item) {
        return item == null ? null : mapper.map(item);
    }
}
