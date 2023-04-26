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
package io.gravitee.rest.api.management.v4.rest.resource.api;

import static io.gravitee.common.http.HttpStatusCode.*;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.common.http.HttpMethod;
import io.gravitee.definition.jackson.datatype.GraviteeMapper;
import io.gravitee.definition.model.DefinitionVersion;
import io.gravitee.definition.model.Properties;
import io.gravitee.definition.model.Proxy;
import io.gravitee.definition.model.VirtualHost;
import io.gravitee.definition.model.flow.Operator;
import io.gravitee.definition.model.services.Services;
import io.gravitee.definition.model.v4.analytics.Analytics;
import io.gravitee.definition.model.v4.endpointgroup.Endpoint;
import io.gravitee.definition.model.v4.endpointgroup.EndpointGroup;
import io.gravitee.definition.model.v4.flow.Flow;
import io.gravitee.definition.model.v4.flow.selector.ChannelSelector;
import io.gravitee.definition.model.v4.flow.selector.ConditionSelector;
import io.gravitee.definition.model.v4.flow.selector.HttpSelector;
import io.gravitee.definition.model.v4.flow.step.Step;
import io.gravitee.definition.model.v4.listener.ListenerType;
import io.gravitee.definition.model.v4.listener.entrypoint.Dlq;
import io.gravitee.definition.model.v4.listener.entrypoint.Entrypoint;
import io.gravitee.definition.model.v4.listener.entrypoint.Qos;
import io.gravitee.definition.model.v4.listener.http.HttpListener;
import io.gravitee.definition.model.v4.listener.http.Path;
import io.gravitee.definition.model.v4.listener.subscription.SubscriptionListener;
import io.gravitee.definition.model.v4.listener.tcp.TcpListener;
import io.gravitee.definition.model.v4.property.Property;
import io.gravitee.definition.model.v4.resource.Resource;
import io.gravitee.definition.model.v4.service.ApiServices;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.rest.api.management.v4.rest.model.ApiV2;
import io.gravitee.rest.api.management.v4.rest.model.ApiV4;
import io.gravitee.rest.api.management.v4.rest.resource.AbstractResourceTest;
import io.gravitee.rest.api.model.EnvironmentEntity;
import io.gravitee.rest.api.model.permissions.RolePermission;
import io.gravitee.rest.api.model.permissions.RolePermissionAction;
import io.gravitee.rest.api.model.v4.api.ApiEntity;
import io.gravitee.rest.api.service.common.GraviteeContext;
import io.gravitee.rest.api.service.exceptions.ApiNotFoundException;
import java.util.*;
import javax.ws.rs.core.Response;
import org.junit.Before;
import org.junit.Test;

/**
 * @author Guillaume LAMIRAND (guillaume.lamirand at graviteesource.com)
 * @author GraviteeSource Team
 */
public class ApiResource_getApiByIdTest extends AbstractResourceTest {

    private static final String API_ID = "my-api";
    private static final String ENVIRONMENT_ID = "my-env";

    private final ObjectMapper mapper = new GraviteeMapper(false);

    @Override
    protected String contextPath() {
        return "/environments/" + ENVIRONMENT_ID + "/apis";
    }

    @Before
    public void init() throws TechnicalException {
        reset(apiServiceV4);
        GraviteeContext.cleanContext();
        GraviteeContext.setCurrentEnvironment(ENVIRONMENT_ID);
        GraviteeContext.setCurrentOrganization(ORGANIZATION);

        EnvironmentEntity environmentEntity = new EnvironmentEntity();
        environmentEntity.setId(ENVIRONMENT_ID);
        environmentEntity.setOrganizationId(ORGANIZATION);
        doReturn(environmentEntity).when(environmentService).findById(ENVIRONMENT_ID);
        doReturn(environmentEntity).when(environmentService).findByOrgAndIdOrHrid(ORGANIZATION, ENVIRONMENT_ID);
    }

    @Test
    public void should_get_api_V4() throws JsonProcessingException {
        doReturn(this.fakeApiEntityV4()).when(apiSearchServiceV4).findGenericById(GraviteeContext.getExecutionContext(), API_ID);

        final Response response = rootTarget(API_ID).request().get();

        assertEquals(OK_200, response.getStatus());

        final ApiV4 responseApi = response.readEntity(ApiV4.class);

        assertNotNull(responseApi);
        assertEquals(API_ID, responseApi.getName());
        assertNotNull(responseApi.getPictureUrl());
        assertNotNull(responseApi.getBackgroundUrl());
        assertNotNull(responseApi.getProperties());
        assertEquals(1, responseApi.getProperties().size());
        assertNotNull(responseApi.getServices());
        assertNotNull(responseApi.getResources());
        assertEquals(1, responseApi.getResources().size());
        assertNotNull(responseApi.getResponseTemplates());
        assertEquals(1, responseApi.getResponseTemplates().size());

        assertNotNull(responseApi.getListeners());
        assertEquals(3, responseApi.getListeners().size());

        io.gravitee.rest.api.management.v4.rest.model.HttpListener httpListener = responseApi.getListeners().get(0).getHttpListener();
        assertNotNull(httpListener);
        assertNotNull(httpListener.getPathMappings());
        assertNotNull(httpListener.getPaths().get(0).getHost());

        io.gravitee.rest.api.management.v4.rest.model.SubscriptionListener subscriptionListener = responseApi
            .getListeners()
            .get(1)
            .getSubscriptionListener();
        assertNotNull(subscriptionListener);
        assertNotNull(subscriptionListener.getEntrypoints());
        var foundEntrypoint = subscriptionListener.getEntrypoints().get(0);
        assertNotNull(foundEntrypoint);
        assertEquals("nice configuration", foundEntrypoint.getConfiguration());
        assertEquals("Entrypoint type", foundEntrypoint.getType());
        assertEquals("SUBSCRIPTION", subscriptionListener.getType().toString());

        io.gravitee.rest.api.management.v4.rest.model.TcpListener tcpListener = responseApi.getListeners().get(2).getTcpListener();
        assertNotNull(tcpListener);
        assertNotNull(tcpListener.getEntrypoints());
        var tcpFoundEntrypoint = tcpListener.getEntrypoints().get(0);
        assertNotNull(tcpFoundEntrypoint);
        assertEquals("nice configuration", tcpFoundEntrypoint.getConfiguration());
        assertEquals("Entrypoint type", tcpFoundEntrypoint.getType());
        assertEquals("TCP", tcpListener.getType().toString());

        assertNotNull(responseApi.getEndpointGroups());
        assertEquals(1, responseApi.getEndpointGroups().size());
        assertNotNull(responseApi.getEndpointGroups().get(0));
        assertNotNull(responseApi.getEndpointGroups().get(0).getEndpoints());
        assertEquals(1, responseApi.getEndpointGroups().get(0).getEndpoints().size());

        var endpoint = responseApi.getEndpointGroups().get(0).getEndpoints().get(0);
        assertNotNull(endpoint);
        assertEquals("http-get", endpoint.getType());

        JsonNode jsonNode = mapper.readTree((String) endpoint.getConfiguration());
        assertEquals("kafka:9092", jsonNode.get("bootstrapServers").asText());
        assertEquals(List.of("demo"), mapper.readValue(jsonNode.get("topics").toString(), List.class));

        assertNotNull(responseApi.getFlows());
        assertEquals(1, responseApi.getFlows().size());

        var flow = responseApi.getFlows().get(0);
        assertNotNull(flow);
        assertEquals("flowName", flow.getName());
        assertEquals(Boolean.TRUE, flow.getEnabled());
        assertNotNull(flow.getTags());
        assertEquals(2, flow.getTags().size());
        assertEquals(Set.of("tag1", "tag2"), flow.getTags());
        assertNotNull(flow.getRequest());
        assertEquals(1, flow.getRequest().size());

        var step = flow.getRequest().get(0);
        assertNotNull(step);
        assertEquals(Boolean.TRUE, step.getEnabled());
        assertEquals("my-policy", step.getPolicy());
        assertEquals("my-condition", step.getCondition());

        assertNotNull(flow.getSelectors());
        assertEquals(3, flow.getSelectors().size());

        var httpSelector = flow.getSelectors().get(0).getHttpSelector();
        assertNotNull(httpSelector);
        assertEquals("/test", httpSelector.getPath());
        assertEquals(io.gravitee.rest.api.management.v4.rest.model.Operator.STARTS_WITH, httpSelector.getPathOperator());
        assertEquals(2, httpSelector.getMethods().size());
        assertEquals(
            Set.of(
                io.gravitee.rest.api.management.v4.rest.model.HttpMethod.GET,
                io.gravitee.rest.api.management.v4.rest.model.HttpMethod.POST
            ),
            httpSelector.getMethods()
        );

        var channelSelector = flow.getSelectors().get(1).getChannelSelector();
        assertEquals("my-channel", channelSelector.getChannel());
        assertEquals(io.gravitee.rest.api.management.v4.rest.model.Operator.STARTS_WITH, channelSelector.getChannelOperator());
        assertEquals(1, channelSelector.getOperations().size());
        assertEquals(
            Set.of(io.gravitee.rest.api.management.v4.rest.model.ChannelSelector.OperationsEnum.SUBSCRIBE),
            channelSelector.getOperations()
        );
        assertEquals(1, channelSelector.getEntrypoints().size());
        assertEquals(Set.of("my-entrypoint"), channelSelector.getEntrypoints());

        var conditionSelector = flow.getSelectors().get(2).getConditionSelector();
        assertEquals("my-condition", conditionSelector.getCondition());
    }

    @Test
    public void should_get_filtered_api_V4() {
        doReturn(this.fakeApiEntityV4()).when(apiSearchServiceV4).findGenericById(GraviteeContext.getExecutionContext(), API_ID);
        doReturn(false)
            .when(permissionService)
            .hasPermission(GraviteeContext.getExecutionContext(), RolePermission.API_DEFINITION, API_ID, RolePermissionAction.READ);

        final Response response = rootTarget(API_ID).request().get();

        assertEquals(OK_200, response.getStatus());

        final ApiV4 responseApi = response.readEntity(ApiV4.class);
        assertNotNull(responseApi);
        assertEquals(API_ID, responseApi.getName());
        assertNull(responseApi.getPictureUrl());
        assertNull(responseApi.getBackgroundUrl());
        assertNull(responseApi.getProperties());
        assertNull(responseApi.getServices());
        assertNull(responseApi.getResources());
        assertNotNull(responseApi.getResponseTemplates());
        assertEquals(0, responseApi.getResponseTemplates().size());
        assertNotNull(responseApi.getListeners());
        assertNotNull(responseApi.getListeners().get(0));
        assertNull((responseApi.getListeners().get(0).getHttpListener()).getPathMappings());
        assertNull((responseApi.getListeners().get(0).getHttpListener()).getPaths().get(0).getHost());
    }

    @Test
    public void should_get_api_V3() throws JsonProcessingException {
        doReturn(this.fakeApiEntityV2()).when(apiSearchServiceV4).findGenericById(GraviteeContext.getExecutionContext(), API_ID);

        final Response response = rootTarget(API_ID).request().get();

        assertEquals(OK_200, response.getStatus());

        final ApiV2 responseApi = response.readEntity(ApiV2.class);

        assertNotNull(responseApi);
        assertEquals(API_ID, responseApi.getName());
        assertNotNull(responseApi.getPictureUrl());
        assertNotNull(responseApi.getBackgroundUrl());
        assertNotNull(responseApi.getProperties());
        assertEquals(1, responseApi.getProperties().size());
        assertNotNull(responseApi.getServices());
        assertNotNull(responseApi.getResources());
        assertEquals(1, responseApi.getResources().size());
        assertNotNull(responseApi.getResponseTemplates());
        assertEquals(1, responseApi.getResponseTemplates().size());

        assertNotNull(responseApi.getProxy());
        assertEquals("/test", responseApi.getProxy().getVirtualHosts().get(0).getPath());
        assertEquals("host.io", responseApi.getProxy().getVirtualHosts().get(0).getHost());
    }

    @Test
    public void should_get_filtered_api_V3() {
        doReturn(this.fakeApiEntityV2()).when(apiSearchServiceV4).findGenericById(GraviteeContext.getExecutionContext(), API_ID);

        doReturn(false)
            .when(permissionService)
            .hasPermission(GraviteeContext.getExecutionContext(), RolePermission.API_DEFINITION, API_ID, RolePermissionAction.READ);

        final Response response = rootTarget(API_ID).request().get();

        assertEquals(OK_200, response.getStatus());

        final ApiV2 responseApi = response.readEntity(ApiV2.class);
        assertNotNull(responseApi);
        assertEquals(API_ID, responseApi.getName());
        assertNull(responseApi.getPictureUrl());
        assertNull(responseApi.getBackgroundUrl());
        assertNull(responseApi.getProperties());
        assertNull(responseApi.getServices());
        assertNull(responseApi.getResources());
        assertNotNull(responseApi.getResponseTemplates());
        assertEquals(0, responseApi.getResponseTemplates().size());
        assertNotNull(responseApi.getProxy());
        assertEquals("/test", responseApi.getProxy().getVirtualHosts().get(0).getPath());
        assertNull(responseApi.getProxy().getVirtualHosts().get(0).getHost());
    }

    @Test
    public void shouldNotGetApiBecauseNotFound() {
        final String UNKNOWN_API = "unknown";

        doThrow(ApiNotFoundException.class).when(apiSearchServiceV4).findGenericById(GraviteeContext.getExecutionContext(), UNKNOWN_API);

        final Response response = rootTarget(UNKNOWN_API).request().get();

        assertEquals(NOT_FOUND_404, response.getStatus());
    }

    private ApiEntity fakeApiEntityV4() {
        var apiEntity = new ApiEntity();
        apiEntity.setDefinitionVersion(DefinitionVersion.V4);
        apiEntity.setId(API_ID);
        apiEntity.setName(API_ID);
        HttpListener httpListener = new HttpListener();
        httpListener.setPaths(List.of(new Path("my.fake.host", "/test")));
        httpListener.setPathMappings(Set.of("/test"));

        SubscriptionListener subscriptionListener = new SubscriptionListener();
        Entrypoint entrypoint = new Entrypoint();
        entrypoint.setType("Entrypoint type");
        entrypoint.setQos(Qos.AT_LEAST_ONCE);
        entrypoint.setDlq(new Dlq("my-endpoint"));
        entrypoint.setConfiguration("nice configuration");
        subscriptionListener.setEntrypoints(List.of(entrypoint));
        subscriptionListener.setType(ListenerType.SUBSCRIPTION);

        TcpListener tcpListener = new TcpListener();
        tcpListener.setType(ListenerType.TCP);
        tcpListener.setEntrypoints(List.of(entrypoint));

        apiEntity.setListeners(List.of(httpListener, subscriptionListener, tcpListener));
        apiEntity.setProperties(List.of(new Property()));
        apiEntity.setServices(new ApiServices());
        apiEntity.setResources(List.of(new Resource()));
        apiEntity.setResponseTemplates(Map.of("key", new HashMap<>()));
        apiEntity.setUpdatedAt(new Date());
        apiEntity.setAnalytics(new Analytics());

        EndpointGroup endpointGroup = new EndpointGroup();
        endpointGroup.setType("http-get");
        Endpoint endpoint = new Endpoint();
        endpoint.setType("http-get");
        endpoint.setConfiguration(
            "{\n" +
            "                        \"bootstrapServers\": \"kafka:9092\",\n" +
            "                        \"topics\": [\n" +
            "                            \"demo\"\n" +
            "                        ],\n" +
            "                        \"producer\": {\n" +
            "                            \"enabled\": false\n" +
            "                        },\n" +
            "                        \"consumer\": {\n" +
            "                            \"encodeMessageId\": true,\n" +
            "                            \"enabled\": true,\n" +
            "                            \"autoOffsetReset\": \"earliest\"\n" +
            "                        }\n" +
            "                    }"
        );
        endpointGroup.setEndpoints(List.of(endpoint));
        apiEntity.setEndpointGroups(List.of(endpointGroup));

        Flow flow = new Flow();
        flow.setName("flowName");
        flow.setEnabled(true);

        Step step = new Step();
        step.setEnabled(true);
        step.setPolicy("my-policy");
        step.setCondition("my-condition");
        flow.setRequest(List.of(step));
        flow.setTags(Set.of("tag1", "tag2"));

        HttpSelector httpSelector = new HttpSelector();
        httpSelector.setPath("/test");
        httpSelector.setMethods(Set.of(HttpMethod.GET, HttpMethod.POST));
        httpSelector.setPathOperator(Operator.STARTS_WITH);

        ChannelSelector channelSelector = new ChannelSelector();
        channelSelector.setChannel("my-channel");
        channelSelector.setChannelOperator(Operator.STARTS_WITH);
        channelSelector.setOperations(Set.of(ChannelSelector.Operation.SUBSCRIBE));
        channelSelector.setEntrypoints(Set.of("my-entrypoint"));

        ConditionSelector conditionSelector = new ConditionSelector();
        conditionSelector.setCondition("my-condition");

        flow.setSelectors(List.of(httpSelector, channelSelector, conditionSelector));
        apiEntity.setFlows(List.of(flow));

        return apiEntity;
    }

    private io.gravitee.rest.api.model.api.ApiEntity fakeApiEntityV2() {
        var apiEntity = new io.gravitee.rest.api.model.api.ApiEntity();
        apiEntity.setGraviteeDefinitionVersion(DefinitionVersion.V2.getLabel());
        apiEntity.setId(API_ID);
        apiEntity.setName(API_ID);

        var proxy = new Proxy();
        proxy.setVirtualHosts(List.of(new VirtualHost("host.io", "/test")));
        apiEntity.setProxy(proxy);
        var properties = new Properties();
        properties.setProperties(List.of(new io.gravitee.definition.model.Property("key", "value")));
        apiEntity.setProperties(properties);
        apiEntity.setServices(new Services());
        apiEntity.setResources(List.of(new io.gravitee.definition.model.plugins.resources.Resource()));
        apiEntity.setResponseTemplates(Map.of("key", new HashMap<>()));
        apiEntity.setUpdatedAt(new Date());

        return apiEntity;
    }
}
