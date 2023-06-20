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
import { Component, Input, OnInit } from '@angular/core';

import { ApiV4 } from '../../../../../entities/management-api-v2';
import { EndpointGroup, toEndpoints } from './api-endpoints-groups.adapter';

@Component({
  selector: 'api-endpoints-groups',
  template: require('./api-endpoints-groups.component.html'),
  styles: [require('./api-endpoints-groups.component.scss')],
})
export class ApiEndpointsGroupsComponent implements OnInit {
  @Input() public api: ApiV4;
  public endpointsDisplayedColumns = ['name', 'options', 'weight', 'actions'];
  public groupsTableData: EndpointGroup[];

  public ngOnInit() {
    this.groupsTableData = toEndpoints(this.api);
  }
}
