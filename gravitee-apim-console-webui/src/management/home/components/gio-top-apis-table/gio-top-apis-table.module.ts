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
import { CommonModule } from '@angular/common';
import { MatLegacyTableModule as MatTableModule } from '@angular/material/legacy-table';
import { MatLegacyCardModule as MatCardModule } from '@angular/material/legacy-card';
import { MatSortModule } from '@angular/material/sort';
import { RouterModule } from '@angular/router';

import { GioTopApisTableComponent } from './gio-top-apis-table.component';

import { GioTableWrapperModule } from '../../../../shared/components/gio-table-wrapper/gio-table-wrapper.module';

@NgModule({
  imports: [CommonModule, RouterModule, MatTableModule, MatCardModule, MatSortModule, GioTableWrapperModule],
  declarations: [GioTopApisTableComponent],
  exports: [GioTopApisTableComponent],
})
export class GioTopApisTableModule {}
