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
package io.gravitee.plugin.entrypoint.sse;

import io.gravitee.gateway.jupiter.api.ApiType;
import io.gravitee.gateway.jupiter.api.ConnectorMode;
import io.gravitee.gateway.jupiter.api.connector.entrypoint.async.EntrypointAsyncConnectorFactory;
import io.gravitee.plugin.entrypoint.sse.configuration.SseEntrypointConnectorConfiguration;
import java.util.Set;

/**
 * @author Guillaume LAMIRAND (guillaume.lamirand at graviteesource.com)
 * @author GraviteeSource Team
 */
public class SseEntrypointConnectorFactory extends EntrypointAsyncConnectorFactory {

    public SseEntrypointConnectorFactory() {
        super(SseEntrypointConnectorConfiguration.class);
    }

    @Override
    public ApiType supportedApi() {
        return SseEntrypointConnector.SUPPORTED_API;
    }

    @Override
    public Set<ConnectorMode> supportedModes() {
        return SseEntrypointConnector.SUPPORTED_MODES;
    }

    @Override
    public SseEntrypointConnector createConnector(final String configuration) {
        return new SseEntrypointConnector();
    }
}
