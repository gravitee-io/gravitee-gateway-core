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
import { NgModule } from '@angular/core';
import { MatBadgeModule } from '@angular/material/badge';
import { MatLegacyButtonModule as MatButtonModule } from '@angular/material/legacy-button';
import { CommonModule } from '@angular/common';
import { GioAvatarModule, GioIconsModule } from '@gravitee/ui-particles-angular';
import { MatLegacyTableModule as MatTableModule } from '@angular/material/legacy-table';
import { MatLegacyTooltipModule as MatTooltipModule } from '@angular/material/legacy-tooltip';
import { MatSortModule } from '@angular/material/sort';
import { RouterModule } from '@angular/router';

import { ApiListComponent } from './api-list.component';

import { GioTableWrapperModule } from '../../../shared/components/gio-table-wrapper/gio-table-wrapper.module';
import { GioPermissionModule } from '../../../shared/components/gio-permission/gio-permission.module';

@NgModule({
  declarations: [ApiListComponent],
  exports: [ApiListComponent],
  imports: [
    CommonModule,
    MatBadgeModule,
    MatButtonModule,
    MatSortModule,
    MatTableModule,
    MatTooltipModule,
    GioAvatarModule,
    GioIconsModule,
    GioTableWrapperModule,
    GioPermissionModule,
    RouterModule,
  ],
})
export class ApiListModule {}
