package io.gravitee.rest.api.service.processor;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

import io.gravitee.common.component.Lifecycle;
import io.gravitee.definition.model.Properties;
import io.gravitee.definition.model.services.Services;
import io.gravitee.rest.api.model.PrimaryOwnerEntity;
import io.gravitee.rest.api.model.api.ApiEntity;
import java.util.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * @author GraviteeSource Team
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@RunWith(MockitoJUnitRunner.class)
@ExtendWith(MockitoExtension.class)
class SynchronizationServiceTest {

    private SynchronizationService synchronizationService;

    @Test
    @DisplayName(
        "GIVEN an entity" +
        "WHEN the required entity fields are retrieved" +
        "THEN only the correct amount of required fields should be returned"
    )
    void thenTheRequiredFieldsShouldBeReturned() {
        ApiEntity entity = new ApiEntity();

        entity.setCrossId("c38d779e-6e7e-472b-8d77-9e6e7e172b08");
        entity.setUpdatedAt(new Date());
        entity.setState(Lifecycle.State.INITIALIZED);
        entity.setPrimaryOwner(new PrimaryOwnerEntity());
        entity.setProperties(new Properties());
        entity.setServices(new Services());
        entity.setEntrypoints(new ArrayList<>());

        int apiEntityRequiredFieldCount = 13;

        List<Object> requiredFields = synchronizationService.getRequiredFieldsForComparison(ApiEntity.class, entity);

        assertThat(requiredFields.size() == apiEntityRequiredFieldCount, is(true));
    }
}
