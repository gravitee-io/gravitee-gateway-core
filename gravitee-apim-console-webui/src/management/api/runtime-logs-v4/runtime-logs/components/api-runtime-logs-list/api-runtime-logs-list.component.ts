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

import { Component, EventEmitter, Input, Output } from '@angular/core';
import { PageEvent } from '@angular/material/paginator';

import { ConnectionLog, Pagination } from '../../../../../../entities/management-api-v2';

@Component({
  selector: 'api-runtime-logs-list',
  template: require('./api-runtime-logs-list.component.html'),
  styles: [require('./api-runtime-logs-list.component.scss')],
})
export class ApiRuntimeLogsListComponent {
  @Input()
  logEnabled: boolean;

  @Input()
  isMessageApi: boolean;

  @Input()
  logs: ConnectionLog[];

  @Output()
  paginationUpdated: EventEmitter<PageEvent> = new EventEmitter<PageEvent>();
  @Output()
  navigateToSettings = new EventEmitter<void>();

  private _pagination?: Pagination;

  pageSizeOptions: number[] = [10, 25, 50, 100];

  @Input()
  get pagination(): Pagination {
    return this._pagination;
  }

  set pagination(value: Pagination) {
    this._pagination = value;

    if (this._pagination.totalCount == null) {
      this._pagination = { ...this._pagination, totalCount: 0 };
    }
  }
}
