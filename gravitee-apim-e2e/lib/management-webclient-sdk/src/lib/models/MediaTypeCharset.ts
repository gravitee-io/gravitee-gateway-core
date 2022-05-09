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
 * @interface MediaTypeCharset
 */
export interface MediaTypeCharset {
    /**
     * 
     * @type {boolean}
     * @memberof MediaTypeCharset
     */
    registered?: boolean;
}

export function MediaTypeCharsetFromJSON(json: any): MediaTypeCharset {
    return MediaTypeCharsetFromJSONTyped(json, false);
}

export function MediaTypeCharsetFromJSONTyped(json: any, ignoreDiscriminator: boolean): MediaTypeCharset {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'registered': !exists(json, 'registered') ? undefined : json['registered'],
    };
}

export function MediaTypeCharsetToJSON(value?: MediaTypeCharset | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'registered': value.registered,
    };
}


