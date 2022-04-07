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

import { exists, mapValues } from '../runtime';
import {
    ApiRequestItem,
    ApiRequestItemFromJSON,
    ApiRequestItemFromJSONTyped,
    ApiRequestItemToJSON,
} from './';

/**
 * 
 * @export
 * @interface ApiRequestItemSearchLogResponse
 */
export interface ApiRequestItemSearchLogResponse {
    /**
     * 
     * @type {number}
     * @memberof ApiRequestItemSearchLogResponse
     */
    total?: number;
    /**
     * 
     * @type {Array<ApiRequestItem>}
     * @memberof ApiRequestItemSearchLogResponse
     */
    logs?: Array<ApiRequestItem>;
    /**
     * 
     * @type {{ [key: string]: { [key: string]: string; }; }}
     * @memberof ApiRequestItemSearchLogResponse
     */
    metadata?: { [key: string]: { [key: string]: string; }; };
}

export function ApiRequestItemSearchLogResponseFromJSON(json: any): ApiRequestItemSearchLogResponse {
    return ApiRequestItemSearchLogResponseFromJSONTyped(json, false);
}

export function ApiRequestItemSearchLogResponseFromJSONTyped(json: any, ignoreDiscriminator: boolean): ApiRequestItemSearchLogResponse {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'total': !exists(json, 'total') ? undefined : json['total'],
        'logs': !exists(json, 'logs') ? undefined : ((json['logs'] as Array<any>).map(ApiRequestItemFromJSON)),
        'metadata': !exists(json, 'metadata') ? undefined : json['metadata'],
    };
}

export function ApiRequestItemSearchLogResponseToJSON(value?: ApiRequestItemSearchLogResponse | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'total': value.total,
        'logs': value.logs === undefined ? undefined : ((value.logs as Array<any>).map(ApiRequestItemToJSON)),
        'metadata': value.metadata,
    };
}


