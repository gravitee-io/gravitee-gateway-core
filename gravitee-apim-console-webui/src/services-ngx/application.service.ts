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

import { Constants } from '../entities/Constants';
import { PagedResult } from '../entities/pagedResult';
import { Application } from '../entities/application/application';

@Injectable({
  providedIn: 'root',
})
export class ApplicationService {
  constructor(private readonly http: HttpClient, @Inject('Constants') private readonly constants: Constants) {}

  getAll(
    params: {
      environmentId?: string;
    } = {},
  ): Observable<any[]> {
    let baseURL = this.constants.env.baseURL;

    if (params.environmentId) {
      baseURL = `${this.constants.org.baseURL}/environments/${params.environmentId}`;
    }

    return this.http.get<any[]>(`${baseURL}/applications`, {
      params: {
        status: 'active',
      },
    });
  }

  list(status?: string, query?: string, order?: string, page = 1, size = 10): Observable<PagedResult<Application>> {
    return this.http.get<PagedResult<Application>>(`${this.constants.env.baseURL}/applications/_paged`, {
      params: {
        page,
        size,
        ...(status ? { status } : {}),
        ...(query ? { query } : {}),
        ...(order ? { order } : {}),
      },
    });
  }

  restore(applicationId: string): Observable<Application> {
    return this.http.post<Application>(`${this.constants.env.baseURL}/applications/${applicationId}/_restore`, {});
  }
}
