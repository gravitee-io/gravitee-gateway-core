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
import { Component, Input, OnDestroy, OnInit } from '@angular/core';
import { FormGroup } from '@angular/forms';
import { Subject } from 'rxjs';
import { takeUntil } from 'rxjs/operators';
import { GioJsonSchema } from '@gravitee/ui-particles-angular';

import { ConnectorPluginsV2Service } from '../../../../../../services-ngx/connector-plugins-v2.service';

@Component({
  selector: 'api-endpoints-group-configuration',
  template: require('./api-endpoints-group-configuration.component.html'),
})
export class ApiEndpointsGroupConfigurationComponent implements OnInit, OnDestroy {
  private unsubscribe$: Subject<boolean> = new Subject<boolean>();

  @Input() configurationForm: FormGroup;

  @Input() endpointGroupType: string;

  public sharedConfigurationSchema: GioJsonSchema;

  constructor(private readonly connectorPluginsV2Service: ConnectorPluginsV2Service) {}

  ngOnInit(): void {
    this.connectorPluginsV2Service
      .getEndpointPluginSharedConfigurationSchema(this.endpointGroupType)
      .pipe(takeUntil(this.unsubscribe$))
      .subscribe({
        next: (sharedConfigSchema) => {
          this.sharedConfigurationSchema = sharedConfigSchema;
        },
      });
  }

  ngOnDestroy(): void {
    this.unsubscribe$.next(true);
    this.unsubscribe$.complete();
  }
}
