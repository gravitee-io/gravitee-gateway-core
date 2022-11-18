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
import { Component, Inject, OnDestroy, OnInit } from "@angular/core";
import { catchError, map, takeUntil, tap } from "rxjs/operators";
import { combineLatest, EMPTY, Subject } from "rxjs";
import { StateService } from "@uirouter/core";
import { CdkDragDrop } from "@angular/cdk/drag-drop";
import { orderBy } from "lodash";

import { UIRouterState, UIRouterStateParams } from "../../../../../ajs-upgraded-providers";
import { PlanService } from "../../../../../services-ngx/plan.service";
import { Api, API_PLAN_STATUS, ApiPlan, ApiPlanStatus } from "../../../../../entities/api";
import { ApiService } from "../../../../../services-ngx/api.service";
import { SnackBarService } from "../../../../../services-ngx/snack-bar.service";

@Component({
  selector: 'api-portal-plan-list',
  template: require('./api-portal-plan-list.component.html'),
  styles: [require('./api-portal-plan-list.component.scss')],
})
export class ApiPortalPlanListComponent implements OnInit, OnDestroy {
  private unsubscribe$: Subject<boolean> = new Subject<boolean>();
  private api: Api;
  public displayedColumns = ['drag-icon', 'name', 'security', 'status', 'deploy-on', 'actions'];
  public plansTableDS: ApiPlan[] = [];
  public isLoadingData = true;
  public apiPlanStatus = API_PLAN_STATUS;
  public status: ApiPlanStatus;

  constructor(
    @Inject(UIRouterStateParams) private readonly ajsStateParams,
    @Inject(UIRouterState) private readonly ajsState: StateService,
    private readonly plansService: PlanService,
    private readonly apiService: ApiService,
    private readonly snackBarService: SnackBarService,
  ) {}

  public ngOnInit(): void {
    this.status = this.ajsStateParams.status ?? 'PUBLISHED';

    combineLatest([this.apiService.get(this.ajsStateParams.apiId), this.plansService.getApiPlans(this.ajsStateParams.apiId, this.status)])
      .pipe(
        takeUntil(this.unsubscribe$),
        tap(([api, plans]) => {
          this.onInit(api, plans);
        }),
        catchError(({ error }) => {
          this.snackBarService.error(error.message);
          return EMPTY;
        }),
      )
      .subscribe();
  }

  public ngOnDestroy(): void {
    this.unsubscribe$.next(true);
    this.unsubscribe$.unsubscribe();
  }

  public searchPlansByStatus(status: ApiPlanStatus): void {
    this.status = status;

    this.plansService
      .getApiPlans(this.ajsStateParams.apiId, status)
      .pipe(
        takeUntil(this.unsubscribe$),
        tap((plans) => this.onInit(this.api, plans)),
        catchError(({ error }) => {
          this.snackBarService.error(error.message);
          return EMPTY;
        }),
      )
      .subscribe();
  }

  public dropRow({ previousIndex, currentIndex }: CdkDragDrop<ApiPlan[], any>) {
    const movedPlan = this.plansTableDS[previousIndex];
    movedPlan.order = currentIndex + 1;

    this.plansService
      .updatePlan(this.api, movedPlan)
      .pipe(
        takeUntil(this.unsubscribe$),
        map(() => this.ngOnInit()),
      )
      .subscribe();
  }

  private onInit(api, plans) {
    this.ajsState.go('management.apis.detail.portal.ng-plans.list', { status: this.status }, { notify: false });
    this.api = api;
    this.plansTableDS = orderBy(plans, 'order', 'asc');
    this.isLoadingData = false;
  }
}
