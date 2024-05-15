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

import static io.gravitee.apim.core.exception.NotAllowedDomainException.noLicenseForFederation;

import io.gravitee.apim.core.UseCase;
import io.gravitee.apim.core.integration.crud_service.IntegrationCrudService;
import io.gravitee.apim.core.integration.exception.IntegrationNotFoundException;
import io.gravitee.apim.core.integration.model.Integration;
import io.gravitee.apim.core.license.domain_service.LicenseDomainService;
import lombok.Builder;

/**
 * @author Remi Baptiste (remi.baptiste at graviteesource.com)
 * @author GraviteeSource Team
 */
@UseCase
public class GetIntegrationUseCase {

    private final IntegrationCrudService integrationCrudService;
    private final LicenseDomainService licenseDomainService;

    public GetIntegrationUseCase(IntegrationCrudService integrationCrudService, LicenseDomainService licenseDomainService) {
        this.integrationCrudService = integrationCrudService;
        this.licenseDomainService = licenseDomainService;
    }

    public GetIntegrationUseCase.Output execute(GetIntegrationUseCase.Input input) {
        var integrationId = input.integrationId();

        var license = licenseDomainService.getLicenseByOrganizationId(input.organizationId());
        if (license.isEmpty()) {
            throw noLicenseForFederation();
        }

        Integration integrationCreated = integrationCrudService
            .findById(integrationId)
            .orElseThrow(() -> new IntegrationNotFoundException(integrationId));

        return new GetIntegrationUseCase.Output(integrationCreated);
    }

    @Builder
    public record Input(String integrationId, String organizationId) {}

    public record Output(Integration integration) {}
}
