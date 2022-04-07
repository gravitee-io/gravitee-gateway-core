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
    CompareConditionAllOf,
    CompareConditionAllOfFromJSON,
    CompareConditionAllOfFromJSONTyped,
    CompareConditionAllOfToJSON,
    Condition,
    ConditionFromJSON,
    ConditionFromJSONTyped,
    ConditionToJSON,
    Projection,
    ProjectionFromJSON,
    ProjectionFromJSONTyped,
    ProjectionToJSON,
} from './';

/**
 * 
 * @export
 * @interface CompareCondition
 */
export interface CompareCondition extends Condition {
    /**
     * 
     * @type {string}
     * @memberof CompareCondition
     */
    property: string;
    /**
     * 
     * @type {string}
     * @memberof CompareCondition
     */
    operator: CompareConditionOperatorEnum;
    /**
     * 
     * @type {number}
     * @memberof CompareCondition
     */
    multiplier: number;
    /**
     * 
     * @type {string}
     * @memberof CompareCondition
     */
    property2: string;
}

export function CompareConditionFromJSON(json: any): CompareCondition {
    return CompareConditionFromJSONTyped(json, false);
}

export function CompareConditionFromJSONTyped(json: any, ignoreDiscriminator: boolean): CompareCondition {
    if ((json === undefined) || (json === null)) {
        return json;
    }
    return {
        ...ConditionFromJSONTyped(json, ignoreDiscriminator),
        'property': json['property'],
        'operator': json['operator'],
        'multiplier': json['multiplier'],
        'property2': json['property2'],
    };
}

export function CompareConditionToJSON(value?: CompareCondition | null): any {
    if (value === undefined) {
        return undefined;
    }
    if (value === null) {
        return null;
    }
    return {
        ...ConditionToJSON(value),
        'property': value.property,
        'operator': value.operator,
        'multiplier': value.multiplier,
        'property2': value.property2,
    };
}

/**
* @export
* @enum {string}
*/
export enum CompareConditionOperatorEnum {
    LT = 'LT',
    LTE = 'LTE',
    GTE = 'GTE',
    GT = 'GT'
}


