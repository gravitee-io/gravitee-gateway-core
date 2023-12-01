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
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { RouterTestingModule } from '@angular/router/testing';
import { createComponentFactory, Spectator } from '@ngneat/spectator/jest';
import { CUSTOM_ELEMENTS_SCHEMA } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

import { ApiLabelsPipe } from '../../../pipes/api-labels.pipe';
import { ApiStatesPipe } from '../../../pipes/api-states.pipe';

import { ApplicationCreationComponent } from './application-creation.component';

describe('ApplicationCreationComponent', () => {
  const enabledApplicationTypes = [
    { id: 'type1', name: 'type1' },
    { id: 'type2', name: 'type2' },
  ];
  const createComponent = createComponentFactory({
    component: ApplicationCreationComponent,
    schemas: [CUSTOM_ELEMENTS_SCHEMA],
    imports: [HttpClientTestingModule, RouterTestingModule, FormsModule, ReactiveFormsModule],
    declarations: [ApiStatesPipe, ApiLabelsPipe],
    providers: [ApiStatesPipe, ApiLabelsPipe, { provide: ActivatedRoute, useValue: { snapshot: { data: { enabledApplicationTypes } } } }],
  });

  let spectator: Spectator<ApplicationCreationComponent>;
  let component: ApplicationCreationComponent;

  beforeEach(() => {
    spectator = createComponent();
    component = spectator.component;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
