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

import { exists, mapValues } from '../runtime';
/**
 * Information about the page, if this page is from an external source.
 * @export
 * @interface Metadata
 */
export interface Metadata {
    /**
     * 
     * @type {string}
     * @memberof Metadata
     */
    name?: string;
    /**
     * 
     * @type {string}
     * @memberof Metadata
     */
    value?: string;
    /**
     * 
     * @type {string}
     * @memberof Metadata
     */
    order?: string;
}

export function MetadataFromJSON(json: any): Metadata {
    return MetadataFromJSONTyped(json, false);
}

export function MetadataFromJSONTyped(json: any, ignoreDiscriminator: boolean): Metadata {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'name': !exists(json, 'name') ? undefined : json['name'],
        'value': !exists(json, 'value') ? undefined : json['value'],
        'order': !exists(json, 'order') ? undefined : json['order'],
    };
}

export function MetadataToJSON(value?: Metadata | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'name': value.name,
        'value': value.value,
        'order': value.order,
    };
}


