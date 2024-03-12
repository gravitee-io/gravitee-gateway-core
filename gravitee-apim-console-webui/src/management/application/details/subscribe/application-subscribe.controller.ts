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
import { IHttpPromise } from 'angular';

import { ActivatedRoute, Router } from '@angular/router';
import { filter, find, forEach, groupBy, includes, join, map, merge, noop } from 'lodash';

import { ApiService } from '../../../../services/api.service';
import ApplicationService from '../../../../services/application.service';
import NotificationService from '../../../../services/notification.service';
import { ApiKeyMode } from '../../../../entities/application/application';
import { PlanSecurityType } from '../../../../entities/plan/plan';
import { Constants } from '../../../../entities/Constants';

class ApplicationSubscribeController {
  private subscriptions: any;
  private application: any;
  private selectedAPI: any;

  private readonly groups = [];
  private readonly subscribedAPIs = [];

  private canAccessSelectedApiPlans = false;
  private apis = [];
  private plans = [];
  private subscribedPlans = [];
  private activatedRoute: ActivatedRoute;

  constructor(
    private ApiService: ApiService,
    private Constants: Constants,
    private ApplicationService: ApplicationService,
    private NotificationService: NotificationService,
    private $mdDialog,
    private ngRouter: Router,
  ) {}

  async $onInit() {
    const subscriptionsByAPI = groupBy(this.subscriptions.data, 'api');

    this.apis = (await this.ApiService.list(null, true, null, null, null, Object.keys(subscriptionsByAPI))).data;

    forEach(subscriptionsByAPI, (subscriptions, api) => {
      this.subscribedAPIs.push(
        merge(find(this.apis, { id: api }), {
          plans: join(
            map(subscriptions, (sub) => this.subscriptions.metadata[sub.plan].name),
            ', ',
          ),
        }),
      );
    });

    this.subscribedPlans = map(this.subscriptions.data, 'plan');
  }

  searchApiByName(searchText): IHttpPromise<any> {
    return this.ApiService.searchApis(searchText, 1, 'name', undefined, undefined, false).then((response) => response.data.data);
  }

  onSelectAPI(api) {
    if (api) {
      const authorizedSecurity = this.getAuthorizedSecurity();
      this.selectedAPI = api;
      this.canAccessSelectedApiPlans = false;
      this.ApiService.getApiPlans(api.id, 'PUBLISHED')
        .then((response) => {
          this.canAccessSelectedApiPlans = true;
          this.plans = filter(response.data, (plan) => {
            plan.alreadySubscribed = includes(this.subscribedPlans, plan.id);
            const subscription = find(this.subscriptions.data, { plan: plan.id });
            plan.pending = subscription && 'PENDING' === subscription.status;
            return includes(authorizedSecurity, plan.security);
          });
          this.selectedAPI = api;
          this.refreshPlansExcludedGroupsNames();
        })
        .catch((error) => {
          if (error.status === 403 && error.interceptorFuture) {
            error.interceptorFuture.cancel();
          }
        });
    } else {
      delete this.plans;
      delete this.selectedAPI;
    }
  }

  getAuthorizedSecurity(): string[] {
    const authorizedSecurity = [PlanSecurityType.API_KEY];
    if (this.application.settings) {
      if (this.application.settings.oauth || (this.application.settings.app && this.application.settings.app.client_id)) {
        authorizedSecurity.push(PlanSecurityType.JWT, PlanSecurityType.OAUTH2);
      }
    }
    return authorizedSecurity;
  }

  async onSubscribe(api, plan) {
    if (this.shouldPromptForKeyMode(plan)) {
      this.selectKeyMode().then((mode) => this.doSubscribe(plan, mode), noop);
    } else {
      await this.doSubscribe(plan);
    }
  }

  async doSubscribe(plan, apikeyMode?: ApiKeyMode) {
    const message = await this.getMessage(plan);

    this.ApplicationService.subscribe(this.application.id, plan.id, message, apikeyMode).then(() => {
      this.NotificationService.show('Subscription to application ' + this.application.name + ' has been successfully created');
      this.ngRouter.navigate(['../'], { relativeTo: this.activatedRoute, queryParamsHandling: 'preserve' });
    });
  }

  async getMessage(plan: any) {
    if (plan.comment_required) {
      const confirm = this.$mdDialog
        .prompt()
        .title('Subscription message')
        .placeholder(plan.comment_message ? plan.comment_message : 'Fill a message to the API owner')
        .ariaLabel('Subscription message')
        .required(true)
        .ok('Confirm')
        .cancel('Cancel');

      return this.$mdDialog.show(confirm, noop);
    }
  }

  onUnsubscribe(api, plan) {
    const alert = this.$mdDialog.confirm({
      title: 'Close subscription?',
      textContent: 'Are you sure you want to close this subscription?',
      ok: 'CLOSE',
      cancel: 'CANCEL',
    });

    this.$mdDialog.show(alert).then(() => {
      this.ApplicationService.closeSubscription(this.application.id, find(this.subscriptions.data, { plan: plan.id }).id).then(() => {
        this.NotificationService.show('Subscription has been successfully closed');
        this.$onInit();
      });
    });
  }

  refreshPlansExcludedGroupsNames() {
    this.plans.forEach(
      (plan) =>
        (plan.excluded_groups_names = plan.excluded_groups?.map(
          (excludedGroupId) => this.groups.find((apiGroup) => apiGroup.id === excludedGroupId)?.name,
        )),
    );
  }

  selectKeyMode() {
    const dialog = {
      controller: 'ApiKeyModeChoiceDialogController',
      controllerAs: '$ctrl',
      template: require('html-loader!/src/components/dialog/apiKeyMode/api-key-mode-choice.dialog.html').default, // eslint-disable-line @typescript-eslint/no-var-requires
      clickOutsideToClose: true,
    };

    return this.$mdDialog.show(dialog);
  }

  shouldPromptForKeyMode(plan: any): boolean {
    return (
      plan.security === PlanSecurityType.API_KEY &&
      this.isSharedApiKeyEnabled &&
      this.application.api_key_mode === ApiKeyMode.UNSPECIFIED &&
      this.apiKeySubscriptionsCount >= 1 &&
      !this.hasAlreadySubscribedApiKeyPlanOnApi(plan)
    );
  }

  get apiKeySubscriptionsCount(): number {
    return this.subscriptions.data.filter((subscription) => subscription.security === PlanSecurityType.API_KEY).length;
  }

  get isSharedApiKeyEnabled(): boolean {
    return this.Constants.env?.settings?.plan?.security?.sharedApiKey?.enabled;
  }

  hasAlreadySubscribedApiKeyPlanOnApi(plan: any): boolean {
    return this.subscriptions.data.some(
      (subscription) => subscription.api === plan.api && subscription.security === PlanSecurityType.API_KEY,
    );
  }
}
ApplicationSubscribeController.$inject = ['ApiService', 'Constants', 'ApplicationService', 'NotificationService', '$mdDialog', 'ngRouter'];

export default ApplicationSubscribeController;
