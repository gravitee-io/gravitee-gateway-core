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

/**
 * 
 * @export
 * @enum {string}
 */
export enum PolicyType {
    REQUEST = 'REQUEST',
    RESPONSE = 'RESPONSE',
    REQUESTRESPONSE = 'REQUEST_RESPONSE'
}

export function PolicyTypeFromJSON(json: any): PolicyType {
    return PolicyTypeFromJSONTyped(json, false);
}

export function PolicyTypeFromJSONTyped(json: any, ignoreDiscriminator: boolean): PolicyType {
    return json as PolicyType;
}

export function PolicyTypeToJSON(value?: PolicyType | null): any {
    return value as any;
}

