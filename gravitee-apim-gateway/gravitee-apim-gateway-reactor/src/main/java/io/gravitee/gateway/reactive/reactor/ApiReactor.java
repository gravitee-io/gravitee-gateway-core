/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.gateway.reactive.reactor;

import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.reactive.core.context.MutableExecutionContext;
import io.gravitee.gateway.reactor.ReactableApi;
import io.gravitee.gateway.reactor.handler.ReactorHandler;
import io.gravitee.node.api.opentelemetry.Tracer;
import io.gravitee.node.opentelemetry.tracer.noop.NoOpTracer;
import io.reactivex.rxjava3.core.Completable;

/**
 * @author Jeoffrey HAEYAERT (jeoffrey.haeyaert at graviteesource.com)
 * @author GraviteeSource Team
 */
public interface ApiReactor<T extends ReactableApi<?>> extends ReactorHandler {
    T api();

    Completable handle(final MutableExecutionContext ctx);

    default void handle(io.gravitee.gateway.api.ExecutionContext context, Handler<io.gravitee.gateway.api.ExecutionContext> endHandler) {
        throw new RuntimeException(new IllegalAccessException("Handle method can't be called on ApiReactor"));
    }
}
