/**
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
package io.gravitee.gateway.report.impl;

import io.gravitee.gateway.report.ReporterService;
import io.gravitee.node.api.healthcheck.Result;
import io.gravitee.reporter.api.Reportable;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.concurrent.CompletableFuture;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class ReporterServiceImpl implements ReporterService {

    @Autowired
    private io.gravitee.node.reporter.ReporterService reporterService;

    @Override
    public void report(Reportable reportable) {
        reporterService.report(reportable);
    }

    @Override
    public CompletableFuture<Result> health() {
        return reporterService.health();
    }
}
