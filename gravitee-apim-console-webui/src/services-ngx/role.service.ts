/*
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import { HttpClient } from '@angular/common/http';
import { Inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import { Constants } from '../entities/Constants';
import { Role, RoleScope } from '../entities/role/role';
import { MembershipListItem } from '../entities/role/membershipListItem';

@Injectable({
  providedIn: 'root',
})
export class RoleService {
  constructor(private readonly http: HttpClient, @Inject('Constants') private readonly constants: Constants) {}

  list(scope: string): Observable<Role[]> {
    return this.http
      .get<Role[]>(`${this.constants.org.baseURL}/configuration/rolescopes/${scope}/roles`)
      .pipe(map((roles) => roles.map((role) => ({ ...role, scope: role.scope.toUpperCase() as RoleScope }))));
  }

  getPermissionsByScopes(): Observable<Record<Extract<RoleScope, 'API' | 'APPLICATION' | 'ENVIRONMENT' | 'ORGANIZATION'>, string[]>> {
    return this.http.get<Record<string, string[]>>(`${this.constants.org.baseURL}/configuration/rolescopes`);
  }

  get(scope: string, roleName: string): Observable<Role> {
    return this.http
      .get<Role>(`${this.constants.org.baseURL}/configuration/rolescopes/${scope}/roles/${roleName}`)
      .pipe(map((role) => ({ ...role, scope: role.scope.toUpperCase() as RoleScope })));
  }

  update(role: Role): Observable<void> {
    return this.http.put<void>(`${this.constants.org.baseURL}/configuration/rolescopes/${role.scope}/roles/${role.name}`, role);
  }

  delete(scope: string, roleName: string): Observable<void> {
    return this.http.delete<void>(`${this.constants.org.baseURL}/configuration/rolescopes/${scope}/roles/${roleName}`);
  }

  listMemberships(scope: string, roleName: string): Observable<MembershipListItem[]> {
    return this.http.get<MembershipListItem[]>(`${this.constants.org.baseURL}/configuration/rolescopes/${scope}/roles/${roleName}/users`);
  }

  deleteMembership(roleScope: string, roleName: string, username: string): Observable<void> {
    return this.http.delete<void>(
      `${this.constants.org.baseURL}/configuration/rolescopes/${roleScope}/roles/${roleName}/users/${username}`,
    );
  }
}
