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
package io.gravitee.rest.api.management.v4.rest;

import io.gravitee.rest.api.management.v4.rest.provider.ObjectMapperResolver;
import java.io.IOException;
import java.security.Principal;
import javax.annotation.Priority;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.SecurityContext;
import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.client.HttpUrlConnectorProvider;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.test.JerseyTest;
import org.glassfish.jersey.test.TestProperties;
import org.junit.After;
import org.junit.Before;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;

/**
 * @author David BRASSELY (brasseld at gmail.com)
 */
public abstract class JerseySpringTest {

    protected static final String USER_NAME = "UnitTests";
    protected static final Principal PRINCIPAL = () -> USER_NAME;
    private JerseyTest _jerseyTest;

    protected abstract String contextPath();

    public final WebTarget rootTarget() {
        return target("", "");
    }

    public final WebTarget rootTarget(final String path) {
        return target(path, "");
    }

    private final WebTarget target(final String path, final String baseURL) {
        String finalPath = "";
        String contextPath = contextPath();
        if (!contextPath.startsWith("/")) {
            finalPath += "/" + contextPath;
        } else {
            finalPath += contextPath;
        }
        if (!path.startsWith("/")) {
            finalPath += "/" + path;
        } else {
            finalPath += path;
        }
        return _jerseyTest.target(baseURL + finalPath);
    }

    @Before
    public void jerseySetUp() throws Exception {
        _jerseyTest.setUp();
    }

    @After
    public void jerseyTearDown() throws Exception {
        _jerseyTest.tearDown();
    }

    @Autowired
    public void setApplicationContext(final ApplicationContext context) {
        _jerseyTest =
            new JerseyTest() {
                @Override
                protected Application configure() {
                    // Find first available port.
                    forceSet(TestProperties.CONTAINER_PORT, "0");

                    ResourceConfig application = new GraviteeManagementV4Application();

                    application.property("contextConfig", context);
                    decorate(application);

                    return application;
                }

                @Override
                protected void configureClient(ClientConfig config) {
                    super.configureClient(config);

                    config.register(ObjectMapperResolver.class);
                    config.register(MultiPartFeature.class);
                    config.property(HttpUrlConnectorProvider.SET_METHOD_WORKAROUND, true);
                }
            };
    }

    protected void decorate(ResourceConfig resourceConfig) {
        resourceConfig.register(AuthenticationFilter.class);

        final HttpServletResponse response = Mockito.mock(HttpServletResponse.class);
        resourceConfig.register(
            new AbstractBinder() {
                @Override
                protected void configure() {
                    bind(response).to(HttpServletResponse.class);
                }
            }
        );
    }

    @Priority(50)
    public static class AuthenticationFilter implements ContainerRequestFilter {

        @Override
        public void filter(final ContainerRequestContext requestContext) throws IOException {
            requestContext.setSecurityContext(
                new SecurityContext() {
                    @Override
                    public Principal getUserPrincipal() {
                        return () -> USER_NAME;
                    }

                    @Override
                    public boolean isUserInRole(String string) {
                        return true;
                    }

                    @Override
                    public boolean isSecure() {
                        return true;
                    }

                    @Override
                    public String getAuthenticationScheme() {
                        return "BASIC";
                    }
                }
            );
        }
    }
}
