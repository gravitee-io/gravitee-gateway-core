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
    AccessControlEntity,
    AccessControlEntityFromJSON,
    AccessControlEntityFromJSONTyped,
    AccessControlEntityToJSON,
    PageSourceEntity,
    PageSourceEntityFromJSON,
    PageSourceEntityFromJSONTyped,
    PageSourceEntityToJSON,
    PageType,
    PageTypeFromJSON,
    PageTypeFromJSONTyped,
    PageTypeToJSON,
    Visibility,
    VisibilityFromJSON,
    VisibilityFromJSONTyped,
    VisibilityToJSON,
} from './';

/**
 * 
 * @export
 * @interface ImportPageEntity
 */
export interface ImportPageEntity {
    /**
     * 
     * @type {PageType}
     * @memberof ImportPageEntity
     */
    type: PageType;
    /**
     * 
     * @type {boolean}
     * @memberof ImportPageEntity
     */
    published?: boolean;
    /**
     * 
     * @type {Visibility}
     * @memberof ImportPageEntity
     */
    visibility?: Visibility;
    /**
     * 
     * @type {string}
     * @memberof ImportPageEntity
     */
    lastContributor?: string;
    /**
     * 
     * @type {PageSourceEntity}
     * @memberof ImportPageEntity
     */
    source?: PageSourceEntity;
    /**
     * 
     * @type {{ [key: string]: string; }}
     * @memberof ImportPageEntity
     */
    _configuration?: { [key: string]: string; };
    /**
     * 
     * @type {boolean}
     * @memberof ImportPageEntity
     */
    excludedAccessControls?: boolean;
    /**
     * 
     * @type {Array<AccessControlEntity>}
     * @memberof ImportPageEntity
     */
    accessControls?: Array<AccessControlEntity>;
    /**
     * 
     * @type {Array<string>}
     * @memberof ImportPageEntity
     */
    excluded_groups?: Array<string>;
}

export function ImportPageEntityFromJSON(json: any): ImportPageEntity {
    return ImportPageEntityFromJSONTyped(json, false);
}

export function ImportPageEntityFromJSONTyped(json: any, ignoreDiscriminator: boolean): ImportPageEntity {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        
        'type': PageTypeFromJSON(json['type']),
        'published': !exists(json, 'published') ? undefined : json['published'],
        'visibility': !exists(json, 'visibility') ? undefined : VisibilityFromJSON(json['visibility']),
        'lastContributor': !exists(json, 'lastContributor') ? undefined : json['lastContributor'],
        'source': !exists(json, 'source') ? undefined : PageSourceEntityFromJSON(json['source']),
        '_configuration': !exists(json, 'configuration') ? undefined : json['configuration'],
        'excludedAccessControls': !exists(json, 'excludedAccessControls') ? undefined : json['excludedAccessControls'],
        'accessControls': !exists(json, 'accessControls') ? undefined : ((json['accessControls'] as Array<any>).map(AccessControlEntityFromJSON)),
        'excluded_groups': !exists(json, 'excluded_groups') ? undefined : json['excluded_groups'],
    };
}

export function ImportPageEntityToJSON(value?: ImportPageEntity | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        
        'type': PageTypeToJSON(value.type),
        'published': value.published,
        'visibility': VisibilityToJSON(value.visibility),
        'lastContributor': value.lastContributor,
        'source': PageSourceEntityToJSON(value.source),
        'configuration': value._configuration,
        'excludedAccessControls': value.excludedAccessControls,
        'accessControls': value.accessControls === undefined ? undefined : ((value.accessControls as Array<any>).map(AccessControlEntityToJSON)),
        'excluded_groups': value.excluded_groups,
    };
}


