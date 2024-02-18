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
import { FormControl } from '@angular/forms';
import { fakeAsync, TestBed, tick } from '@angular/core/testing';
import { HttpTestingController } from '@angular/common/http/testing';

import { contextPathAsyncValidator } from './context-path-async-validator.directive';

import { ApiV2Service } from '../../../services-ngx/api-v2.service';
import { CONSTANTS_TESTING, GioHttpTestingModule } from '../../testing';
import { Constants } from '../../../entities/Constants';

describe('ContextPathAsyncValidator', () => {
  const fakeConstants = CONSTANTS_TESTING;
  let httpTestingController: HttpTestingController;
  let apiV2Service: ApiV2Service;

  beforeEach(() => {
    TestBed.configureTestingModule({
      imports: [GioHttpTestingModule],
      providers: [
        {
          provide: Constants,
          useValue: fakeConstants,
        },
      ],
    });
    httpTestingController = TestBed.inject(HttpTestingController);
    apiV2Service = TestBed.inject(ApiV2Service);
  });

  it('should be invalid context path', fakeAsync(async () => {
    const formControl = new FormControl('', {
      asyncValidators: contextPathAsyncValidator(apiV2Service),
    });
    formControl.markAsDirty();
    formControl.patchValue('/echo');
    tick(250);
    const req = httpTestingController.expectOne({ url: `${CONSTANTS_TESTING.env.v2BaseURL}/apis/_verify/paths`, method: 'POST' });
    expect(req.request.body.apiId).toBeUndefined();
    expect(req.request.body.paths).toEqual([{ path: '/echo' }]);
    req.flush({ ok: false, reason: 'The path [/echo/] is already covered by an other API.' });
    expect(formControl.hasError('listeners')).toBeTruthy();
  }));

  it('should be invalid context path for api', fakeAsync(async () => {
    const formControl = new FormControl('', {
      asyncValidators: contextPathAsyncValidator(apiV2Service, 'api-id'),
    });
    formControl.markAsDirty();
    formControl.patchValue('/echo');
    tick(250);
    const req = httpTestingController.expectOne({ url: `${CONSTANTS_TESTING.env.v2BaseURL}/apis/_verify/paths`, method: 'POST' });
    expect(req.request.body.apiId).toEqual('api-id');
    expect(req.request.body.paths).toEqual([{ path: '/echo' }]);
    req.flush({ ok: false, reason: 'The path [/echo/] is already covered by an other API.' });
    expect(formControl.hasError('listeners')).toBeTruthy();
  }));

  it('should be valid context path', fakeAsync(() => {
    const formControl = new FormControl('', {
      asyncValidators: contextPathAsyncValidator(apiV2Service),
    });
    formControl.markAsDirty();
    formControl.patchValue('valid-host');
    tick(250);
    const req = httpTestingController.expectOne({ url: `${CONSTANTS_TESTING.env.v2BaseURL}/apis/_verify/paths`, method: 'POST' });
    req.flush({ ok: true });
    expect(formControl.hasError('listeners')).toBeFalsy();
  }));
});
