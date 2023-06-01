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

import { ChangeDetectorRef, Component, OnDestroy, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { MatDialog } from '@angular/material/dialog';
import { of, Subject } from 'rxjs';
import { catchError, takeUntil, tap } from 'rxjs/operators';
import { GioConfirmDialogComponent, GioConfirmDialogData } from '@gravitee/ui-particles-angular';
import { isEqual } from 'lodash';

import { Step2Entrypoints2ConfigComponent } from './step-2-entrypoints-2-config.component';

import { ApiCreationStepService } from '../../services/api-creation-step.service';
import { ConnectorVM } from '../../models/ConnectorVM';
import {
  GioConnectorDialogComponent,
  GioConnectorDialogData,
} from '../../../../../../components/gio-connector-dialog/gio-connector-dialog.component';
import { IconService } from '../../../../../../services-ngx/icon.service';
import { ConnectorPluginsV2Service } from '../../../../../../services-ngx/connector-plugins-v2.service';

@Component({
  selector: 'step-2-entrypoints-1-list',
  template: require('./step-2-entrypoints-1-list.component.html'),
  styles: [require('./step-2-entrypoints-1-list.component.scss'), require('../api-creation-steps-common.component.scss')],
})
export class Step2Entrypoints1ListComponent implements OnInit, OnDestroy {
  private unsubscribe$: Subject<void> = new Subject<void>();

  public formGroup: FormGroup;

  public entrypoints: ConnectorVM[];

  constructor(
    private readonly formBuilder: FormBuilder,
    private readonly connectorPluginsV2Service: ConnectorPluginsV2Service,
    private readonly matDialog: MatDialog,
    private readonly confirmDialog: MatDialog,
    private readonly stepService: ApiCreationStepService,
    private readonly changeDetectorRef: ChangeDetectorRef,
    private readonly iconService: IconService,
  ) {}

  ngOnInit(): void {
    const currentStepPayload = this.stepService.payload;

    this.formGroup = this.formBuilder.group({
      selectedEntrypointsIds: this.formBuilder.control(
        (currentStepPayload.selectedEntrypoints ?? []).map((p) => p.id),
        [Validators.required],
      ),
    });

    this.connectorPluginsV2Service
      .listAsyncEntrypointPlugins()
      .pipe(takeUntil(this.unsubscribe$))
      .subscribe((entrypointPlugins) => {
        this.entrypoints = entrypointPlugins.map((entrypoint) => ({
          id: entrypoint.id,
          name: entrypoint.name,
          description: entrypoint.description,
          isEnterprise: entrypoint.id.endsWith('-advanced'),
          supportedListenerType: entrypoint.supportedListenerType,
          icon: this.iconService.registerSvg(entrypoint.id, entrypoint.icon),
        }));
        this.changeDetectorRef.detectChanges();
      });
  }

  ngOnDestroy() {
    this.unsubscribe$.next();
    this.unsubscribe$.unsubscribe();
  }

  save() {
    const previousSelection = this.stepService.payload?.selectedEntrypoints?.map((e) => e.id);
    const newSelection = this.formGroup.value.selectedEntrypointsIds;

    if (previousSelection && !isEqual(newSelection, previousSelection)) {
      // When changing the entrypoint selection, all previously filled steps will be marked as invalid to force user to review the whole configuration.
      return this.confirmDialog
        .open<GioConfirmDialogComponent, GioConfirmDialogData, boolean>(GioConfirmDialogComponent, {
          data: {
            title: 'Are you sure?',
            content:
              'Changing the entrypoints list has impact on all following configuration steps. You will have to review all previously entered data.',
            confirmButton: 'Validate',
            cancelButton: 'Discard',
          },
        })
        .afterClosed()
        .subscribe((confirmed) => {
          if (confirmed) {
            this.stepService.invalidateAllNextSteps();
            this.saveChanges();
          }
        });
    }
    return this.saveChanges();
  }

  goBack(): void {
    this.stepService.goToPreviousStep();
  }

  onMoreInfoClick(event, entrypoint: ConnectorVM) {
    event.stopPropagation();

    this.connectorPluginsV2Service
      .getEntrypointPluginMoreInformation(entrypoint.id)
      .pipe(
        takeUntil(this.unsubscribe$),
        catchError(() => of({})),
        tap((pluginMoreInformation) => {
          this.matDialog
            .open<GioConnectorDialogComponent, GioConnectorDialogData, boolean>(GioConnectorDialogComponent, {
              data: {
                name: entrypoint.name,
                pluginMoreInformation,
              },
              role: 'alertdialog',
              id: 'moreInfoDialog',
            })
            .afterClosed()
            .pipe(takeUntil(this.unsubscribe$))
            .subscribe();
        }),
      )
      .subscribe();
  }

  private saveChanges() {
    const selectedEntrypointsIds = this.formGroup.getRawValue().selectedEntrypointsIds ?? [];
    const selectedEntrypoints = this.entrypoints
      .map(({ id, name, supportedListenerType, icon }) => ({ id, name, supportedListenerType, icon }))
      .filter((e) => selectedEntrypointsIds.includes(e.id));

    this.stepService.validStep((previousPayload) => ({
      ...previousPayload,
      selectedEntrypoints,
    }));

    return this.stepService.goToNextStep({
      groupNumber: 2,
      component: Step2Entrypoints2ConfigComponent,
    });
  }
}
