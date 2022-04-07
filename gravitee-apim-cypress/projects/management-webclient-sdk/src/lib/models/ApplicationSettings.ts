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
    OAuthClientSettings,
    OAuthClientSettingsFromJSON,
    OAuthClientSettingsFromJSONTyped,
    OAuthClientSettingsToJSON,
    SimpleApplicationSettings,
    SimpleApplicationSettingsFromJSON,
    SimpleApplicationSettingsFromJSONTyped,
    SimpleApplicationSettingsToJSON,
} from './';

/**
 * 
 * @export
 * @interface ApplicationSettings
 */
export interface ApplicationSettings {
    /**
     * 
     * @type {SimpleApplicationSettings}
     * @memberof ApplicationSettings
     */
    app?: SimpleApplicationSettings;
    /**
     * 
     * @type {OAuthClientSettings}
     * @memberof ApplicationSettings
     */
    oauth?: OAuthClientSettings;
}

export function ApplicationSettingsFromJSON(json: any): ApplicationSettings {
    return ApplicationSettingsFromJSONTyped(json, false);
}

export function ApplicationSettingsFromJSONTyped(json: any, ignoreDiscriminator: boolean): ApplicationSettings {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'app': !exists(json, 'app') ? undefined : SimpleApplicationSettingsFromJSON(json['app']),
        'oauth': !exists(json, 'oauth') ? undefined : OAuthClientSettingsFromJSON(json['oauth']),
    };
}

export function ApplicationSettingsToJSON(value?: ApplicationSettings | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'app': SimpleApplicationSettingsToJSON(value.app),
        'oauth': OAuthClientSettingsToJSON(value.oauth),
    };
}


