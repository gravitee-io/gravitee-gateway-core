/* tslint:disable */
/* eslint-disable */
/**
 * Gravitee.io - Management API
 * No description provided (generated by Openapi Generator https://github.com/openapitools/openapi-generator)
 *
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
export enum PromotionEntityStatus {
    CREATED = 'CREATED',
    TOBEVALIDATED = 'TO_BE_VALIDATED',
    ACCEPTED = 'ACCEPTED',
    REJECTED = 'REJECTED',
    ERROR = 'ERROR'
}

export function PromotionEntityStatusFromJSON(json: any): PromotionEntityStatus {
    return PromotionEntityStatusFromJSONTyped(json, false);
}

export function PromotionEntityStatusFromJSONTyped(json: any, ignoreDiscriminator: boolean): PromotionEntityStatus {
    return json as PromotionEntityStatus;
}

export function PromotionEntityStatusToJSON(value?: PromotionEntityStatus | null): any {
    return value as any;
}

