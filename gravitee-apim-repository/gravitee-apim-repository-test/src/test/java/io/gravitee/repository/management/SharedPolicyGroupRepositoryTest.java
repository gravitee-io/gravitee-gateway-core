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
package io.gravitee.repository.management;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Fail.fail;

import io.gravitee.definition.model.v4.ApiType;
import io.gravitee.repository.management.model.SharedPolicyGroup;
import io.gravitee.repository.management.model.SharedPolicyGroupLifecycleState;
import java.util.Date;
import java.util.Optional;
import org.junit.Test;

public class SharedPolicyGroupRepositoryTest extends AbstractManagementRepositoryTest {

    @Override
    protected String getTestCasesPath() {
        return "/data/sharedPolicyGroup-tests/";
    }

    @Test
    public void should_create() throws Exception {
        var date = new Date();
        final SharedPolicyGroup sharedPolicyGroup = SharedPolicyGroup
            .builder()
            .id("id_create_test")
            .name("name")
            .version(1)
            .description("description")
            .crossId("crossId")
            .apiType(ApiType.PROXY)
            .definition("definition")
            .lifecycleState(SharedPolicyGroupLifecycleState.UNDEPLOYED)
            .environmentId("environmentId")
            .organizationId("organizationId")
            .deployedAt(date)
            .createdAt(date)
            .updatedAt(date)
            .build();

        final SharedPolicyGroup create = sharedPolicyGroupRepository.create(sharedPolicyGroup);

        assertThat(create.getName()).isEqualTo(sharedPolicyGroup.getName());
        assertThat(create.getVersion()).isEqualTo(sharedPolicyGroup.getVersion());
        assertThat(create.getDescription()).isEqualTo(sharedPolicyGroup.getDescription());
        assertThat(create.getCrossId()).isEqualTo(sharedPolicyGroup.getCrossId());
        assertThat(create.getApiType()).isEqualTo(sharedPolicyGroup.getApiType());
        assertThat(create.getDefinition()).isEqualTo(sharedPolicyGroup.getDefinition());
        assertThat(create.getLifecycleState()).isEqualTo(sharedPolicyGroup.getLifecycleState());
        assertThat(create.getEnvironmentId()).isEqualTo(sharedPolicyGroup.getEnvironmentId());
        assertThat(create.getOrganizationId()).isEqualTo(sharedPolicyGroup.getOrganizationId());
        assertThat(create.getDeployedAt()).isEqualTo(sharedPolicyGroup.getDeployedAt());
        assertThat(create.getCreatedAt()).isEqualTo(create.getCreatedAt());
        assertThat(create.getUpdatedAt()).isEqualTo(create.getUpdatedAt());
    }

    @Test
    public void should_update() throws Exception {
        var date = new Date();
        final SharedPolicyGroup toUpdate = SharedPolicyGroup
            .builder()
            .id("id_update_test")
            .name("new name")
            .version(2)
            .description("new description")
            .crossId("new crossId")
            .apiType(ApiType.MESSAGE)
            .definition("new definition")
            .lifecycleState(SharedPolicyGroupLifecycleState.DEPLOYED)
            .environmentId("new environmentId")
            .organizationId("new organizationId")
            .createdAt(date)
            .updatedAt(date)
            .build();

        final SharedPolicyGroup update = sharedPolicyGroupRepository.update(toUpdate);

        assertThat(update.getName()).isEqualTo(toUpdate.getName());
        assertThat(update.getVersion()).isEqualTo(toUpdate.getVersion());
        assertThat(update.getDescription()).isEqualTo(toUpdate.getDescription());
        assertThat(update.getCrossId()).isEqualTo(toUpdate.getCrossId());
        assertThat(update.getApiType()).isEqualTo(toUpdate.getApiType());
        assertThat(update.getDefinition()).isEqualTo(toUpdate.getDefinition());
        assertThat(update.getLifecycleState()).isEqualTo(toUpdate.getLifecycleState());
        assertThat(update.getEnvironmentId()).isEqualTo(toUpdate.getEnvironmentId());
        assertThat(update.getOrganizationId()).isEqualTo(toUpdate.getOrganizationId());
        assertThat(update.getDeployedAt()).isEqualTo(toUpdate.getDeployedAt());
        assertThat(update.getCreatedAt()).isEqualTo(toUpdate.getCreatedAt());
        assertThat(update.getUpdatedAt()).isEqualTo(toUpdate.getUpdatedAt());
    }

    @Test
    public void should_find_by_id() throws Exception {
        Optional<SharedPolicyGroup> optional = sharedPolicyGroupRepository.findById("id_find-by-id_test");
        assertThat(optional).isPresent();
        assertThat(optional.get().getName()).isEqualTo("name");
        assertThat(optional.get().getVersion()).isEqualTo(1);
        assertThat(optional.get().getDescription()).isEqualTo("description");
        assertThat(optional.get().getCrossId()).isEqualTo("crossId");
        assertThat(optional.get().getApiType()).isEqualTo(ApiType.PROXY);
        assertThat(optional.get().getDefinition()).isEqualTo("definition");
        assertThat(optional.get().getLifecycleState()).isEqualTo(SharedPolicyGroupLifecycleState.UNDEPLOYED);
        assertThat(optional.get().getEnvironmentId()).isEqualTo("environmentId");
        assertThat(optional.get().getOrganizationId()).isEqualTo("organizationId");
        assertThat(optional.get().getDeployedAt()).isNotNull();
        assertThat(optional.get().getCreatedAt()).isNotNull();
        assertThat(optional.get().getUpdatedAt()).isNotNull();
    }

    @Test
    public void should_not_findById_missing() throws Exception {
        Optional<SharedPolicyGroup> optional = sharedPolicyGroupRepository.findById("id-does-not-exist");
        assertThat(optional.isEmpty()).as("SharedPolicyGroup is found").isTrue();
    }

    @Test
    public void should_delete() throws Exception {
        Optional<SharedPolicyGroup> optional = sharedPolicyGroupRepository.findById("id_delete_test");
        assertThat(optional).as("SharedPolicyGroup to delete has not been found").isPresent();
        sharedPolicyGroupRepository.delete("id_delete_test");
        optional = sharedPolicyGroupRepository.findById("id_delete_test");
        assertThat(optional).as("SharedPolicyGroup to delete has not been deleted").isNotPresent();
    }

    @Test(expected = IllegalStateException.class)
    public void should_findAll() throws Exception {
        sharedPolicyGroupRepository.findAll();
        fail("An exception must be thrown");
    }
}
