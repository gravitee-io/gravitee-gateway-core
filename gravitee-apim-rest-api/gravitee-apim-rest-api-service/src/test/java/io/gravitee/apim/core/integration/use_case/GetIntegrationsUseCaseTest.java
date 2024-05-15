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
package io.gravitee.apim.core.integration.use_case;

import static java.util.Optional.of;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.in;

import fixtures.core.model.IntegrationFixture;
import inmemory.InMemoryAlternative;
import inmemory.IntegrationQueryServiceInMemory;
import inmemory.LicenseCrudServiceInMemory;
import io.gravitee.apim.core.exception.NotAllowedDomainException;
import io.gravitee.apim.core.integration.query_service.IntegrationQueryService;
import io.gravitee.apim.core.license.domain_service.LicenseDomainService;
import io.gravitee.common.data.domain.Page;
import io.gravitee.rest.api.model.common.Pageable;
import io.gravitee.rest.api.model.common.PageableImpl;
import java.util.List;
import java.util.stream.Stream;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class GetIntegrationsUseCaseTest {

    private static final String ENV_ID = "my-env";
    private static final String ORGANIZATION_ID = "my-org";
    private static final int PAGE_NUMBER = 1;
    private static final int PAGE_SIZE = 5;
    private static final Pageable pageable = new PageableImpl(PAGE_NUMBER, PAGE_SIZE);

    IntegrationQueryServiceInMemory integrationQueryServiceInMemory = new IntegrationQueryServiceInMemory();
    LicenseCrudServiceInMemory licenseCrudService = new LicenseCrudServiceInMemory();

    GetIntegrationsUseCase usecase;

    @BeforeEach
    void setUp() {
        IntegrationQueryService integrationQueryService = integrationQueryServiceInMemory;
        usecase = new GetIntegrationsUseCase(integrationQueryService, new LicenseDomainService(licenseCrudService));

        licenseCrudService.createOrganizationLicense(ORGANIZATION_ID, "license-base64");
    }

    @AfterEach
    void tearDown() {
        Stream.of(integrationQueryServiceInMemory, licenseCrudService).forEach(InMemoryAlternative::reset);
    }

    @Test
    void should_return_integrations_with_specific_env_id() {
        //Given
        var expected = IntegrationFixture.anIntegration();
        integrationQueryServiceInMemory.initWith(
            List.of(expected, IntegrationFixture.anIntegration("falseEnvID"), IntegrationFixture.anIntegration("anotherFalseEnvID"))
        );
        var input = GetIntegrationsUseCase.Input
            .builder()
            .organizationId(ORGANIZATION_ID)
            .environmentId(ENV_ID)
            .pageable(of(pageable))
            .build();

        //When
        var output = usecase.execute(input);

        //Then
        assertThat(output).isNotNull();
        assertThat(output.integrations())
            .extracting(Page::getContent, Page::getPageNumber, Page::getPageElements, Page::getTotalElements)
            .containsExactly(
                List.of(expected),
                PAGE_NUMBER,
                output.integrations().getPageElements(),
                (long) output.integrations().getContent().size()
            );
    }

    @Test
    void should_return_integrations_with_default_pageable() {
        //Given
        var expected = IntegrationFixture.anIntegration();
        integrationQueryServiceInMemory.initWith(List.of(expected));
        var input = new GetIntegrationsUseCase.Input(ORGANIZATION_ID, ENV_ID);

        //When
        var output = usecase.execute(input);

        //Then
        assertThat(output).isNotNull();
        assertThat(output.integrations())
            .extracting(Page::getContent, Page::getPageNumber, Page::getPageElements, Page::getTotalElements)
            .containsExactly(
                List.of(expected),
                PAGE_NUMBER,
                output.integrations().getPageElements(),
                (long) output.integrations().getContent().size()
            );
    }

    @Test
    void should_throw_when_no_license_found() {
        // Given
        licenseCrudService.reset();

        // When
        var throwable = Assertions.catchThrowable(() -> usecase.execute(new GetIntegrationsUseCase.Input(ORGANIZATION_ID, ENV_ID)));

        // Then
        assertThat(throwable).isInstanceOf(NotAllowedDomainException.class);
    }
}
