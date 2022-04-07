/* tslint:disable */
/* eslint-disable */
/**
 * Gravitee.io - Management API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
 * The version of the OpenAPI document: 3.18.0-SNAPSHOT
 * 
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import * as runtime from '../runtime';
import {
    ClientRegistrationProviderEntity,
    ClientRegistrationProviderEntityFromJSON,
    ClientRegistrationProviderEntityToJSON,
    ClientRegistrationProviderListItem,
    ClientRegistrationProviderListItemFromJSON,
    ClientRegistrationProviderListItemToJSON,
    NewClientRegistrationProviderEntity,
    NewClientRegistrationProviderEntityFromJSON,
    NewClientRegistrationProviderEntityToJSON,
    UpdateClientRegistrationProviderEntity,
    UpdateClientRegistrationProviderEntityFromJSON,
    UpdateClientRegistrationProviderEntityToJSON,
} from '../models';

export interface CreateClientRegistrationProviderRequest {
    envId: string;
    orgId: string;
    newClientRegistrationProviderEntity: NewClientRegistrationProviderEntity;
}

export interface DeleteClientRegistrationProviderRequest {
    clientRegistrationProvider: string;
    envId: string;
    orgId: string;
}

export interface GetClientRegistrationProviderRequest {
    clientRegistrationProvider: string;
    envId: string;
    orgId: string;
}

export interface GetClientRegistrationProvidersRequest {
    envId: string;
    orgId: string;
}

export interface UpdateClientRegistrationProviderRequest {
    clientRegistrationProvider: string;
    envId: string;
    orgId: string;
    updateClientRegistrationProviderEntity: UpdateClientRegistrationProviderEntity;
}

/**
 * 
 */
export class ClientRegistrationProvidersApi extends runtime.BaseAPI {

    /**
     * User must have the PORTAL_CLIENT_REGISTRATION_PROVIDER[CREATE] permission to use this service
     * Create a client registration provider
     */
    async createClientRegistrationProviderRaw(requestParameters: CreateClientRegistrationProviderRequest): Promise<runtime.ApiResponse<ClientRegistrationProviderEntity>> {
        if (requestParameters.envId === null || requestParameters.envId === undefined) {
            throw new runtime.RequiredError('envId','Required parameter requestParameters.envId was null or undefined when calling createClientRegistrationProvider.');
        }

        if (requestParameters.orgId === null || requestParameters.orgId === undefined) {
            throw new runtime.RequiredError('orgId','Required parameter requestParameters.orgId was null or undefined when calling createClientRegistrationProvider.');
        }

        if (requestParameters.newClientRegistrationProviderEntity === null || requestParameters.newClientRegistrationProviderEntity === undefined) {
            throw new runtime.RequiredError('newClientRegistrationProviderEntity','Required parameter requestParameters.newClientRegistrationProviderEntity was null or undefined when calling createClientRegistrationProvider.');
        }

        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/organizations/{orgId}/environments/{envId}/configuration/applications/registration/providers`.replace(`{${"envId"}}`, encodeURIComponent(String(requestParameters.envId))).replace(`{${"orgId"}}`, encodeURIComponent(String(requestParameters.orgId))),
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: NewClientRegistrationProviderEntityToJSON(requestParameters.newClientRegistrationProviderEntity),
        });

        return new runtime.JSONApiResponse(response, (jsonValue) => ClientRegistrationProviderEntityFromJSON(jsonValue));
    }

    /**
     * User must have the PORTAL_CLIENT_REGISTRATION_PROVIDER[CREATE] permission to use this service
     * Create a client registration provider
     */
    async createClientRegistrationProvider(requestParameters: CreateClientRegistrationProviderRequest): Promise<ClientRegistrationProviderEntity> {
        const response = await this.createClientRegistrationProviderRaw(requestParameters);
        return await response.value();
    }

    /**
     * User must have the PORTAL_CLIENT_REGISTRATION_PROVIDER[DELETE] permission to use this service
     * Delete a client registration provider
     */
    async deleteClientRegistrationProviderRaw(requestParameters: DeleteClientRegistrationProviderRequest): Promise<runtime.ApiResponse<void>> {
        if (requestParameters.clientRegistrationProvider === null || requestParameters.clientRegistrationProvider === undefined) {
            throw new runtime.RequiredError('clientRegistrationProvider','Required parameter requestParameters.clientRegistrationProvider was null or undefined when calling deleteClientRegistrationProvider.');
        }

        if (requestParameters.envId === null || requestParameters.envId === undefined) {
            throw new runtime.RequiredError('envId','Required parameter requestParameters.envId was null or undefined when calling deleteClientRegistrationProvider.');
        }

        if (requestParameters.orgId === null || requestParameters.orgId === undefined) {
            throw new runtime.RequiredError('orgId','Required parameter requestParameters.orgId was null or undefined when calling deleteClientRegistrationProvider.');
        }

        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/organizations/{orgId}/environments/{envId}/configuration/applications/registration/providers/{clientRegistrationProvider}`.replace(`{${"clientRegistrationProvider"}}`, encodeURIComponent(String(requestParameters.clientRegistrationProvider))).replace(`{${"envId"}}`, encodeURIComponent(String(requestParameters.envId))).replace(`{${"orgId"}}`, encodeURIComponent(String(requestParameters.orgId))),
            method: 'DELETE',
            headers: headerParameters,
            query: queryParameters,
        });

        return new runtime.VoidApiResponse(response);
    }

    /**
     * User must have the PORTAL_CLIENT_REGISTRATION_PROVIDER[DELETE] permission to use this service
     * Delete a client registration provider
     */
    async deleteClientRegistrationProvider(requestParameters: DeleteClientRegistrationProviderRequest): Promise<void> {
        await this.deleteClientRegistrationProviderRaw(requestParameters);
    }

    /**
     * User must have the PORTAL_CLIENT_REGISTRATION_PROVIDER[READ] permission to use this service
     * Get a client registration provider
     */
    async getClientRegistrationProviderRaw(requestParameters: GetClientRegistrationProviderRequest): Promise<runtime.ApiResponse<ClientRegistrationProviderEntity>> {
        if (requestParameters.clientRegistrationProvider === null || requestParameters.clientRegistrationProvider === undefined) {
            throw new runtime.RequiredError('clientRegistrationProvider','Required parameter requestParameters.clientRegistrationProvider was null or undefined when calling getClientRegistrationProvider.');
        }

        if (requestParameters.envId === null || requestParameters.envId === undefined) {
            throw new runtime.RequiredError('envId','Required parameter requestParameters.envId was null or undefined when calling getClientRegistrationProvider.');
        }

        if (requestParameters.orgId === null || requestParameters.orgId === undefined) {
            throw new runtime.RequiredError('orgId','Required parameter requestParameters.orgId was null or undefined when calling getClientRegistrationProvider.');
        }

        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/organizations/{orgId}/environments/{envId}/configuration/applications/registration/providers/{clientRegistrationProvider}`.replace(`{${"clientRegistrationProvider"}}`, encodeURIComponent(String(requestParameters.clientRegistrationProvider))).replace(`{${"envId"}}`, encodeURIComponent(String(requestParameters.envId))).replace(`{${"orgId"}}`, encodeURIComponent(String(requestParameters.orgId))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        });

        return new runtime.JSONApiResponse(response, (jsonValue) => ClientRegistrationProviderEntityFromJSON(jsonValue));
    }

    /**
     * User must have the PORTAL_CLIENT_REGISTRATION_PROVIDER[READ] permission to use this service
     * Get a client registration provider
     */
    async getClientRegistrationProvider(requestParameters: GetClientRegistrationProviderRequest): Promise<ClientRegistrationProviderEntity> {
        const response = await this.getClientRegistrationProviderRaw(requestParameters);
        return await response.value();
    }

    /**
     * User must have the PORTAL_CLIENT_REGISTRATION_PROVIDER[READ] permission to use this service
     * Get the list of client registration providers
     */
    async getClientRegistrationProvidersRaw(requestParameters: GetClientRegistrationProvidersRequest): Promise<runtime.ApiResponse<Array<ClientRegistrationProviderListItem>>> {
        if (requestParameters.envId === null || requestParameters.envId === undefined) {
            throw new runtime.RequiredError('envId','Required parameter requestParameters.envId was null or undefined when calling getClientRegistrationProviders.');
        }

        if (requestParameters.orgId === null || requestParameters.orgId === undefined) {
            throw new runtime.RequiredError('orgId','Required parameter requestParameters.orgId was null or undefined when calling getClientRegistrationProviders.');
        }

        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/organizations/{orgId}/environments/{envId}/configuration/applications/registration/providers`.replace(`{${"envId"}}`, encodeURIComponent(String(requestParameters.envId))).replace(`{${"orgId"}}`, encodeURIComponent(String(requestParameters.orgId))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        });

        return new runtime.JSONApiResponse(response, (jsonValue) => jsonValue.map(ClientRegistrationProviderListItemFromJSON));
    }

    /**
     * User must have the PORTAL_CLIENT_REGISTRATION_PROVIDER[READ] permission to use this service
     * Get the list of client registration providers
     */
    async getClientRegistrationProviders(requestParameters: GetClientRegistrationProvidersRequest): Promise<Array<ClientRegistrationProviderListItem>> {
        const response = await this.getClientRegistrationProvidersRaw(requestParameters);
        return await response.value();
    }

    /**
     * User must have the PORTAL_CLIENT_REGISTRATION_PROVIDER[UPDATE] permission to use this service
     * Update a client registration provider
     */
    async updateClientRegistrationProviderRaw(requestParameters: UpdateClientRegistrationProviderRequest): Promise<runtime.ApiResponse<ClientRegistrationProviderEntity>> {
        if (requestParameters.clientRegistrationProvider === null || requestParameters.clientRegistrationProvider === undefined) {
            throw new runtime.RequiredError('clientRegistrationProvider','Required parameter requestParameters.clientRegistrationProvider was null or undefined when calling updateClientRegistrationProvider.');
        }

        if (requestParameters.envId === null || requestParameters.envId === undefined) {
            throw new runtime.RequiredError('envId','Required parameter requestParameters.envId was null or undefined when calling updateClientRegistrationProvider.');
        }

        if (requestParameters.orgId === null || requestParameters.orgId === undefined) {
            throw new runtime.RequiredError('orgId','Required parameter requestParameters.orgId was null or undefined when calling updateClientRegistrationProvider.');
        }

        if (requestParameters.updateClientRegistrationProviderEntity === null || requestParameters.updateClientRegistrationProviderEntity === undefined) {
            throw new runtime.RequiredError('updateClientRegistrationProviderEntity','Required parameter requestParameters.updateClientRegistrationProviderEntity was null or undefined when calling updateClientRegistrationProvider.');
        }

        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/organizations/{orgId}/environments/{envId}/configuration/applications/registration/providers/{clientRegistrationProvider}`.replace(`{${"clientRegistrationProvider"}}`, encodeURIComponent(String(requestParameters.clientRegistrationProvider))).replace(`{${"envId"}}`, encodeURIComponent(String(requestParameters.envId))).replace(`{${"orgId"}}`, encodeURIComponent(String(requestParameters.orgId))),
            method: 'PUT',
            headers: headerParameters,
            query: queryParameters,
            body: UpdateClientRegistrationProviderEntityToJSON(requestParameters.updateClientRegistrationProviderEntity),
        });

        return new runtime.JSONApiResponse(response, (jsonValue) => ClientRegistrationProviderEntityFromJSON(jsonValue));
    }

    /**
     * User must have the PORTAL_CLIENT_REGISTRATION_PROVIDER[UPDATE] permission to use this service
     * Update a client registration provider
     */
    async updateClientRegistrationProvider(requestParameters: UpdateClientRegistrationProviderRequest): Promise<ClientRegistrationProviderEntity> {
        const response = await this.updateClientRegistrationProviderRaw(requestParameters);
        return await response.value();
    }

}
