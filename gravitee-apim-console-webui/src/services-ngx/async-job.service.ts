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

import { Inject, Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';

import { Constants } from '../entities/Constants';
import { PagedResult } from '../entities/pagedResult';
import { AsyncJob, AsyncJobStatus, AsyncJobType } from '../entities/async-job';

@Injectable({
  providedIn: 'root',
})
export class AsyncJobService {
  private url: string = `${this.constants.env.v2BaseURL}/async-jobs`;

  constructor(private readonly httpClient: HttpClient, @Inject(Constants) private readonly constants: Constants) {}

  public listAsyncJobs(query: AsyncJobListQuery, page: number, size: number): Observable<PagedResult<AsyncJob>> {
    return this.httpClient.get<PagedResult<AsyncJob>>(`${this.url}`, {
      params: {
        page,
        size,
        ...query,
      },
    });
  }
}

export interface AsyncJobListQuery {
  status?: AsyncJobStatus;
  type?: AsyncJobType;
  sourceId?: string;
}
