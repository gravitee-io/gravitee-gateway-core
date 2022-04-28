/* tslint:disable */
/* eslint-disable */
/**
 * Gravitee.io Portal Rest API
 * API dedicated to the devportal part of Gravitee
 *
 * Contact: contact@graviteesource.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import * as runtime from '../runtime';
import {
    ChangeUserPasswordInput,
    ChangeUserPasswordInputFromJSON,
    ChangeUserPasswordInputToJSON,
    CustomUserFields,
    CustomUserFieldsFromJSON,
    CustomUserFieldsToJSON,
    ErrorResponse,
    ErrorResponseFromJSON,
    ErrorResponseToJSON,
    FinalizeRegistrationInput,
    FinalizeRegistrationInputFromJSON,
    FinalizeRegistrationInputToJSON,
    RegisterUserInput,
    RegisterUserInputFromJSON,
    RegisterUserInputToJSON,
    ResetUserPasswordInput,
    ResetUserPasswordInputFromJSON,
    ResetUserPasswordInputToJSON,
    User,
    UserFromJSON,
    UserToJSON,
    UsersResponse,
    UsersResponseFromJSON,
    UsersResponseToJSON,
} from '../models';

export interface ChangeUserPasswordRequest {
    changeUserPasswordInput?: ChangeUserPasswordInput;
}

export interface FinalizeUserRegistrationRequest {
    finalizeRegistrationInput?: FinalizeRegistrationInput;
}

export interface GetUserAvatarRequest {
    userId: string;
}

export interface GetUsersRequest {
    page?: number;
    size?: number;
    q?: string;
}

export interface RegisterNewUserRequest {
    registerUserInput?: RegisterUserInput;
}

export interface ResetUserPasswordRequest {
    resetUserPasswordInput?: ResetUserPasswordInput;
}

/**
 * 
 */
export class UsersApi extends runtime.BaseAPI {

    /**
     * Perform the password update for a user 
     * Change a user\'s password after a reset requests
     */
    async changeUserPasswordRaw(requestParameters: ChangeUserPasswordRequest): Promise<runtime.ApiResponse<User>> {
        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/users/_change_password`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: ChangeUserPasswordInputToJSON(requestParameters.changeUserPasswordInput),
        });

        return new runtime.JSONApiResponse(response, (jsonValue) => UserFromJSON(jsonValue));
    }

    /**
     * Perform the password update for a user 
     * Change a user\'s password after a reset requests
     */
    async changeUserPassword(requestParameters: ChangeUserPasswordRequest): Promise<User> {
        const response = await this.changeUserPasswordRaw(requestParameters);
        return await response.value();
    }

    /**
     * Create a new user for the portal.  User registration must be enabled. 
     * Finalize user registration.
     */
    async finalizeUserRegistrationRaw(requestParameters: FinalizeUserRegistrationRequest): Promise<runtime.ApiResponse<User>> {
        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/users/registration/_finalize`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: FinalizeRegistrationInputToJSON(requestParameters.finalizeRegistrationInput),
        });

        return new runtime.JSONApiResponse(response, (jsonValue) => UserFromJSON(jsonValue));
    }

    /**
     * Create a new user for the portal.  User registration must be enabled. 
     * Finalize user registration.
     */
    async finalizeUserRegistration(requestParameters: FinalizeUserRegistrationRequest): Promise<User> {
        const response = await this.finalizeUserRegistrationRaw(requestParameters);
        return await response.value();
    }

    /**
     * Retrieve a user\'s avatar. 
     * Retrieve a user\'s avatar
     */
    async getUserAvatarRaw(requestParameters: GetUserAvatarRequest): Promise<runtime.ApiResponse<Blob>> {
        if (requestParameters.userId === null || requestParameters.userId === undefined) {
            throw new runtime.RequiredError('userId','Required parameter requestParameters.userId was null or undefined when calling getUserAvatar.');
        }

        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/users/{userId}/avatar`.replace(`{${"userId"}}`, encodeURIComponent(String(requestParameters.userId))),
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        });

        return new runtime.BlobApiResponse(response);
    }

    /**
     * Retrieve a user\'s avatar. 
     * Retrieve a user\'s avatar
     */
    async getUserAvatar(requestParameters: GetUserAvatarRequest): Promise<Blob> {
        const response = await this.getUserAvatarRaw(requestParameters);
        return await response.value();
    }

    /**
     * List platform users from identity providers.  User must have the MANAGEMENT_USERS[READ] permission. 
     * List platform users.
     */
    async getUsersRaw(requestParameters: GetUsersRequest): Promise<runtime.ApiResponse<UsersResponse>> {
        const queryParameters: runtime.HTTPQuery = {};

        if (requestParameters.page !== undefined) {
            queryParameters['page'] = requestParameters.page;
        }

        if (requestParameters.size !== undefined) {
            queryParameters['size'] = requestParameters.size;
        }

        if (requestParameters.q !== undefined) {
            queryParameters['q'] = requestParameters.q;
        }

        const headerParameters: runtime.HTTPHeaders = {};

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/users/_search`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
        });

        return new runtime.JSONApiResponse(response, (jsonValue) => UsersResponseFromJSON(jsonValue));
    }

    /**
     * List platform users from identity providers.  User must have the MANAGEMENT_USERS[READ] permission. 
     * List platform users.
     */
    async getUsers(requestParameters: GetUsersRequest): Promise<UsersResponse> {
        const response = await this.getUsersRaw(requestParameters);
        return await response.value();
    }

    /**
     * Provide the list of custom user fields asked to the new users. 
     * List all the Custom User Fields.
     */
    async listCustomUserFieldsRaw(): Promise<runtime.ApiResponse<Array<CustomUserFields>>> {
        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/configuration/users/custom-fields`,
            method: 'GET',
            headers: headerParameters,
            query: queryParameters,
        });

        return new runtime.JSONApiResponse(response, (jsonValue) => jsonValue.map(CustomUserFieldsFromJSON));
    }

    /**
     * Provide the list of custom user fields asked to the new users. 
     * List all the Custom User Fields.
     */
    async listCustomUserFields(): Promise<Array<CustomUserFields>> {
        const response = await this.listCustomUserFieldsRaw();
        return await response.value();
    }

    /**
     * Register a new user for the portal. As a result, an email is sent with an activation link.  User registration must be enabled.\\ A SMTP server must have been configured. 
     * Register a new user.
     */
    async registerNewUserRaw(requestParameters: RegisterNewUserRequest): Promise<runtime.ApiResponse<User>> {
        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/users/registration`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: RegisterUserInputToJSON(requestParameters.registerUserInput),
        });

        return new runtime.JSONApiResponse(response, (jsonValue) => UserFromJSON(jsonValue));
    }

    /**
     * Register a new user for the portal. As a result, an email is sent with an activation link.  User registration must be enabled.\\ A SMTP server must have been configured. 
     * Register a new user.
     */
    async registerNewUser(requestParameters: RegisterNewUserRequest): Promise<User> {
        const response = await this.registerNewUserRaw(requestParameters);
        return await response.value();
    }

    /**
     * Send an email with a link so the user with this email can provide a new password. The user must be internally managed and active. 
     * Reset a user\'s password
     */
    async resetUserPasswordRaw(requestParameters: ResetUserPasswordRequest): Promise<runtime.ApiResponse<void>> {
        const queryParameters: runtime.HTTPQuery = {};

        const headerParameters: runtime.HTTPHeaders = {};

        headerParameters['Content-Type'] = 'application/json';

        if (this.configuration && (this.configuration.username !== undefined || this.configuration.password !== undefined)) {
            headerParameters["Authorization"] = "Basic " + btoa(this.configuration.username + ":" + this.configuration.password);
        }
        const response = await this.request({
            path: `/users/_reset_password`,
            method: 'POST',
            headers: headerParameters,
            query: queryParameters,
            body: ResetUserPasswordInputToJSON(requestParameters.resetUserPasswordInput),
        });

        return new runtime.VoidApiResponse(response);
    }

    /**
     * Send an email with a link so the user with this email can provide a new password. The user must be internally managed and active. 
     * Reset a user\'s password
     */
    async resetUserPassword(requestParameters: ResetUserPasswordRequest): Promise<void> {
        await this.resetUserPasswordRaw(requestParameters);
    }

}
