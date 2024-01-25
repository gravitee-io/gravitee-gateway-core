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

import { ApiCreationStep, ApiCreationStepperService, NewApiCreationStep } from './api-creation-stepper.service';

import { ApiCreationPayload } from '../models/ApiCreationPayload';

/**
 * This service is injected in each step component to provide a way to access the payload and to navigate between steps.
 */
@Injectable()
export class ApiCreationStepService {
  constructor(
    @Inject('isFactory') private readonly stepper: ApiCreationStepperService,
    @Inject('isFactory') public readonly step: ApiCreationStep,
  ) {}

  public get payload(): ApiCreationPayload {
    return this.stepper.compileStepPayload(this.step);
  }

  public validStep(patchPayload: ApiCreationStep['patchPayload']): void {
    this.stepper.validStep(patchPayload);
  }

  public goToPreviousStep(): void {
    this.stepper.goToPreviousStep();
  }

  public goToStepLabel(stepLabel: string) {
    this.stepper.goToStepLabel(stepLabel);
  }

  public goToNextStep(step: NewApiCreationStep): void {
    this.stepper.goToNextStep(step);
  }

  public finishStepper(): void {
    this.stepper.finishStepper();
  }

  removeAllNextSteps() {
    this.stepper.removeAllNextSteps();
  }

  invalidateAllNextSteps() {
    this.stepper.invalidateAllNextSteps();
  }
}
