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

import { exists, mapValues } from '../runtime';
/**
 * 
 * @export
 * @interface MonitoringGC
 */
export interface MonitoringGC {
    /**
     * 
     * @type {number}
     * @memberof MonitoringGC
     */
    old_collection_count?: number;
    /**
     * 
     * @type {number}
     * @memberof MonitoringGC
     */
    old_collection_time_in_millis?: number;
    /**
     * 
     * @type {number}
     * @memberof MonitoringGC
     */
    young_collection_count?: number;
    /**
     * 
     * @type {number}
     * @memberof MonitoringGC
     */
    young_collection_time_in_millis?: number;
}

export function MonitoringGCFromJSON(json: any): MonitoringGC {
    return MonitoringGCFromJSONTyped(json, false);
}

export function MonitoringGCFromJSONTyped(json: any, ignoreDiscriminator: boolean): MonitoringGC {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'old_collection_count': !exists(json, 'old_collection_count') ? undefined : json['old_collection_count'],
        'old_collection_time_in_millis': !exists(json, 'old_collection_time_in_millis') ? undefined : json['old_collection_time_in_millis'],
        'young_collection_count': !exists(json, 'young_collection_count') ? undefined : json['young_collection_count'],
        'young_collection_time_in_millis': !exists(json, 'young_collection_time_in_millis') ? undefined : json['young_collection_time_in_millis'],
    };
}

export function MonitoringGCToJSON(value?: MonitoringGC | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'old_collection_count': value.old_collection_count,
        'old_collection_time_in_millis': value.old_collection_time_in_millis,
        'young_collection_count': value.young_collection_count,
        'young_collection_time_in_millis': value.young_collection_time_in_millis,
    };
}


