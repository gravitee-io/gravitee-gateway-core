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
package io.gravitee.rest.api.service.impl;

import static io.gravitee.repository.management.model.Api.AuditEvent.API_CREATED;
import static io.gravitee.repository.management.model.Api.AuditEvent.API_DELETED;
import static io.gravitee.repository.management.model.Api.AuditEvent.API_ROLLBACKED;
import static io.gravitee.repository.management.model.Api.AuditEvent.API_UPDATED;
import static io.gravitee.repository.management.model.Visibility.PUBLIC;
import static io.gravitee.repository.management.model.Workflow.AuditEvent.API_REVIEW_ACCEPTED;
import static io.gravitee.repository.management.model.Workflow.AuditEvent.API_REVIEW_ASKED;
import static io.gravitee.repository.management.model.Workflow.AuditEvent.API_REVIEW_REJECTED;
import static io.gravitee.rest.api.model.EventType.PUBLISH_API;
import static io.gravitee.rest.api.model.PageType.SWAGGER;
import static io.gravitee.rest.api.model.WorkflowState.DRAFT;
import static io.gravitee.rest.api.model.WorkflowType.REVIEW;
import static io.gravitee.rest.api.service.impl.search.lucene.transformer.ApiDocumentTransformer.FIELD_DEFINITION_VERSION;
import static java.util.Collections.emptyList;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonList;
import static java.util.Collections.singletonMap;
import static java.util.Comparator.comparing;
import static java.util.Optional.of;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;
import static java.util.stream.Collectors.toSet;
import static org.apache.commons.lang3.StringUtils.isBlank;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.common.base.Strings;
import io.gravitee.common.data.domain.Page;
import io.gravitee.common.util.DataEncryptor;
import io.gravitee.definition.model.DefinitionContext;
import io.gravitee.definition.model.DefinitionVersion;
import io.gravitee.definition.model.Endpoint;
import io.gravitee.definition.model.EndpointGroup;
import io.gravitee.definition.model.Logging;
import io.gravitee.definition.model.LoggingMode;
import io.gravitee.definition.model.Proxy;
import io.gravitee.definition.model.Rule;
import io.gravitee.definition.model.VirtualHost;
import io.gravitee.definition.model.flow.Flow;
import io.gravitee.definition.model.flow.Step;
import io.gravitee.definition.model.plugins.resources.Resource;
import io.gravitee.definition.model.services.discovery.EndpointDiscoveryService;
import io.gravitee.definition.model.services.healthcheck.HealthCheckService;
import io.gravitee.repository.exceptions.TechnicalException;
import io.gravitee.repository.management.api.ApiFieldInclusionFilter;
import io.gravitee.repository.management.api.ApiQualityRuleRepository;
import io.gravitee.repository.management.api.ApiRepository;
import io.gravitee.repository.management.api.search.ApiCriteria;
import io.gravitee.repository.management.api.search.ApiFieldExclusionFilter;
import io.gravitee.repository.management.model.Api;
import io.gravitee.repository.management.model.ApiLifecycleState;
import io.gravitee.repository.management.model.Audit;
import io.gravitee.repository.management.model.Event;
import io.gravitee.repository.management.model.GroupEvent;
import io.gravitee.repository.management.model.LifecycleState;
import io.gravitee.repository.management.model.NotificationReferenceType;
import io.gravitee.repository.management.model.Visibility;
import io.gravitee.repository.management.model.Workflow;
import io.gravitee.repository.management.model.flow.FlowReferenceType;
import io.gravitee.rest.api.model.ApiMetadataEntity;
import io.gravitee.rest.api.model.CategoryEntity;
import io.gravitee.rest.api.model.EventEntity;
import io.gravitee.rest.api.model.EventQuery;
import io.gravitee.rest.api.model.EventType;
import io.gravitee.rest.api.model.GroupEntity;
import io.gravitee.rest.api.model.ImportSwaggerDescriptorEntity;
import io.gravitee.rest.api.model.InlinePictureEntity;
import io.gravitee.rest.api.model.MembershipEntity;
import io.gravitee.rest.api.model.MembershipMemberType;
import io.gravitee.rest.api.model.MembershipReferenceType;
import io.gravitee.rest.api.model.MetadataFormat;
import io.gravitee.rest.api.model.NewApiMetadataEntity;
import io.gravitee.rest.api.model.PageEntity;
import io.gravitee.rest.api.model.PlanEntity;
import io.gravitee.rest.api.model.PlanStatus;
import io.gravitee.rest.api.model.PolicyEntity;
import io.gravitee.rest.api.model.PrimaryOwnerEntity;
import io.gravitee.rest.api.model.PropertiesEntity;
import io.gravitee.rest.api.model.PropertyEntity;
import io.gravitee.rest.api.model.ReviewEntity;
import io.gravitee.rest.api.model.RoleEntity;
import io.gravitee.rest.api.model.SubscriptionEntity;
import io.gravitee.rest.api.model.TagReferenceType;
import io.gravitee.rest.api.model.UpdateApiMetadataEntity;
import io.gravitee.rest.api.model.UserEntity;
import io.gravitee.rest.api.model.WorkflowReferenceType;
import io.gravitee.rest.api.model.WorkflowState;
import io.gravitee.rest.api.model.alert.AlertReferenceType;
import io.gravitee.rest.api.model.alert.AlertTriggerEntity;
import io.gravitee.rest.api.model.api.ApiDeploymentEntity;
import io.gravitee.rest.api.model.api.ApiEntity;
import io.gravitee.rest.api.model.api.ApiEntrypointEntity;
import io.gravitee.rest.api.model.api.ApiQuery;
import io.gravitee.rest.api.model.api.NewApiEntity;
import io.gravitee.rest.api.model.api.RollbackApiEntity;
import io.gravitee.rest.api.model.api.SwaggerApiEntity;
import io.gravitee.rest.api.model.api.UpdateApiEntity;
import io.gravitee.rest.api.model.api.header.ApiHeaderEntity;
import io.gravitee.rest.api.model.common.Pageable;
import io.gravitee.rest.api.model.common.PageableImpl;
import io.gravitee.rest.api.model.common.Sortable;
import io.gravitee.rest.api.model.notification.GenericNotificationConfigEntity;
import io.gravitee.rest.api.model.parameters.Key;
import io.gravitee.rest.api.model.parameters.ParameterReferenceType;
import io.gravitee.rest.api.model.permissions.ApiPermission;
import io.gravitee.rest.api.model.permissions.RolePermissionAction;
import io.gravitee.rest.api.model.permissions.RoleScope;
import io.gravitee.rest.api.model.permissions.SystemRole;
import io.gravitee.rest.api.model.settings.ApiPrimaryOwnerMode;
import io.gravitee.rest.api.model.v4.api.GenericApiEntity;
import io.gravitee.rest.api.model.v4.api.GenericApiModel;
import io.gravitee.rest.api.service.AlertService;
import io.gravitee.rest.api.service.ApiDuplicatorService;
import io.gravitee.rest.api.service.ApiHeaderService;
import io.gravitee.rest.api.service.ApiMetadataService;
import io.gravitee.rest.api.service.ApiService;
import io.gravitee.rest.api.service.AuditService;
import io.gravitee.rest.api.service.CategoryService;
import io.gravitee.rest.api.service.ConnectorService;
import io.gravitee.rest.api.service.EmailService;
import io.gravitee.rest.api.service.EnvironmentService;
import io.gravitee.rest.api.service.EventService;
import io.gravitee.rest.api.service.GenericNotificationConfigService;
import io.gravitee.rest.api.service.GroupService;
import io.gravitee.rest.api.service.JupiterModeService;
import io.gravitee.rest.api.service.MediaService;
import io.gravitee.rest.api.service.MembershipService;
import io.gravitee.rest.api.service.NotifierService;
import io.gravitee.rest.api.service.PageService;
import io.gravitee.rest.api.service.ParameterService;
import io.gravitee.rest.api.service.PlanService;
import io.gravitee.rest.api.service.PolicyService;
import io.gravitee.rest.api.service.PortalNotificationConfigService;
import io.gravitee.rest.api.service.ResourceService;
import io.gravitee.rest.api.service.RoleService;
import io.gravitee.rest.api.service.SubscriptionService;
import io.gravitee.rest.api.service.SwaggerService;
import io.gravitee.rest.api.service.TagService;
import io.gravitee.rest.api.service.TopApiService;
import io.gravitee.rest.api.service.UserService;
import io.gravitee.rest.api.service.VirtualHostService;
import io.gravitee.rest.api.service.WorkflowService;
import io.gravitee.rest.api.service.builder.EmailNotificationBuilder;
import io.gravitee.rest.api.service.common.ExecutionContext;
import io.gravitee.rest.api.service.common.UuidString;
import io.gravitee.rest.api.service.configuration.flow.FlowService;
import io.gravitee.rest.api.service.converter.ApiConverter;
import io.gravitee.rest.api.service.exceptions.ApiAlreadyExistsException;
import io.gravitee.rest.api.service.exceptions.ApiMetadataNotFoundException;
import io.gravitee.rest.api.service.exceptions.ApiNotDeletableException;
import io.gravitee.rest.api.service.exceptions.ApiNotFoundException;
import io.gravitee.rest.api.service.exceptions.ApiNotManagedException;
import io.gravitee.rest.api.service.exceptions.ApiRunningStateException;
import io.gravitee.rest.api.service.exceptions.DefinitionVersionException;
import io.gravitee.rest.api.service.exceptions.EndpointMissingException;
import io.gravitee.rest.api.service.exceptions.EndpointNameInvalidException;
import io.gravitee.rest.api.service.exceptions.GroupsNotFoundException;
import io.gravitee.rest.api.service.exceptions.HealthcheckInheritanceException;
import io.gravitee.rest.api.service.exceptions.InvalidDataException;
import io.gravitee.rest.api.service.exceptions.LifecycleStateChangeNotAllowedException;
import io.gravitee.rest.api.service.exceptions.PaginationInvalidException;
import io.gravitee.rest.api.service.exceptions.TagNotAllowedException;
import io.gravitee.rest.api.service.exceptions.TechnicalManagementException;
import io.gravitee.rest.api.service.impl.search.SearchResult;
import io.gravitee.rest.api.service.impl.upgrade.DefaultMetadataUpgrader;
import io.gravitee.rest.api.service.jackson.ser.api.ApiSerializer;
import io.gravitee.rest.api.service.migration.APIV1toAPIV2Converter;
import io.gravitee.rest.api.service.notification.ApiHook;
import io.gravitee.rest.api.service.notification.HookScope;
import io.gravitee.rest.api.service.notification.NotificationParamsBuilder;
import io.gravitee.rest.api.service.notification.NotificationTemplateService;
import io.gravitee.rest.api.service.processor.SynchronizationService;
import io.gravitee.rest.api.service.search.SearchEngineService;
import io.gravitee.rest.api.service.search.query.Query;
import io.gravitee.rest.api.service.search.query.QueryBuilder;
import io.gravitee.rest.api.service.v4.ApiAuthorizationService;
import io.gravitee.rest.api.service.v4.ApiEntrypointService;
import io.gravitee.rest.api.service.v4.ApiNotificationService;
import io.gravitee.rest.api.service.v4.ApiTemplateService;
import io.gravitee.rest.api.service.v4.PrimaryOwnerService;
import io.gravitee.rest.api.service.v4.validation.CorsValidationService;
import io.gravitee.rest.api.service.v4.validation.LoggingValidationService;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Lazy;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.stereotype.Component;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author Nicolas GERAUD (nicolas.geraud at graviteesource.com)
 * @author Azize ELAMRANI (azize at graviteesource.com)
 * @author GraviteeSource Team
 */
@Component
public class ApiServiceImpl extends AbstractService implements ApiService {

    public static final String API_DEFINITION_CONTET_FIELD = "definition_context";
    public static final String API_DEFINITION_CONTEXT_FIELD_ORIGIN = "origin";
    public static final String API_DEFINITION_CONTEXT_FIELD_MODE = "mode";
    private static final Logger LOGGER = LoggerFactory.getLogger(ApiServiceImpl.class);
    private static final String ENDPOINTS_DELIMITER = "\n";

    @Lazy
    @Autowired
    private ApiRepository apiRepository;

    @Lazy
    @Autowired
    private ApiQualityRuleRepository apiQualityRuleRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private EventService eventService;

    @Autowired
    private UserService userService;

    @Autowired
    private PageService pageService;

    @Autowired
    private MembershipService membershipService;

    @Autowired
    private GroupService groupService;

    @Autowired
    private PlanService planService;

    @Autowired
    private SynchronizationService synchronizationService;

    @Autowired
    private ApiMetadataService apiMetadataService;

    @Autowired
    private SubscriptionService subscriptionService;

    @Autowired
    private AuditService auditService;

    @Autowired
    private TopApiService topApiService;

    @Autowired
    private GenericNotificationConfigService genericNotificationConfigService;

    @Autowired
    private PortalNotificationConfigService portalNotificationConfigService;

    @Autowired
    private NotifierService notifierService;

    @Autowired
    private SwaggerService swaggerService;

    @Autowired
    private SearchEngineService searchEngineService;

    @Autowired
    private ApiHeaderService apiHeaderService;

    @Autowired
    private NotificationTemplateService notificationTemplateService;

    @Autowired
    private ParameterService parameterService;

    @Autowired
    private TagService tagService;

    @Autowired
    private WorkflowService workflowService;

    @Autowired
    private VirtualHostService virtualHostService;

    @Autowired
    private AlertService alertService;

    @Autowired
    private RoleService roleService;

    @Autowired
    private CategoryService categoryService;

    @Autowired
    private PolicyService policyService;

    @Autowired
    private MediaService mediaService;

    @Autowired
    private EmailService emailService;

    @Autowired
    private APIV1toAPIV2Converter apiv1toAPIV2Converter;

    @Autowired
    private DataEncryptor dataEncryptor;

    @Autowired
    private ApiDuplicatorService apiDuplicatorService;

    @Autowired
    private ConnectorService connectorService;

    @Autowired
    private EnvironmentService environmentService;

    @Autowired
    private ApiConverter apiConverter;

    @Autowired
    private ResourceService resourceService;

    @Autowired
    private FlowService flowService;

    @Autowired
    private JupiterModeService jupiterModeService;

    @Value("${configuration.default-api-icon:}")
    private String defaultApiIcon;

    @Autowired
    private PrimaryOwnerService primaryOwnerService;

    @Autowired
    private ApiNotificationService apiNotificationService;

    @Autowired
    private LoggingValidationService loggingValidationService;

    @Autowired
    private CorsValidationService corsValidationService;

    @Autowired
    private ApiEntrypointService apiEntrypointService;

    @Autowired
    private ApiTemplateService apiTemplateService;

    @Autowired
    private ApiAuthorizationService apiAuthorizationService;

    @Override
    public ApiEntity createFromSwagger(
        ExecutionContext executionContext,
        final SwaggerApiEntity swaggerApiEntity,
        final String userId,
        final ImportSwaggerDescriptorEntity swaggerDescriptor
    ) throws ApiAlreadyExistsException {
        final ApiEntity createdApi = createFromUpdateApiEntity(executionContext, swaggerApiEntity, userId, swaggerDescriptor);

        apiMetadataService.create(executionContext, swaggerApiEntity.getMetadata(), createdApi.getId());

        return createdApi;
    }

    private void checkGroupExistence(Set<String> groups) {
        // check the existence of groups
        if (groups != null && !groups.isEmpty()) {
            try {
                groupService.findByIds(new HashSet(groups));
            } catch (GroupsNotFoundException gnfe) {
                throw new InvalidDataException("These groups [" + gnfe.getParameters().get("groups") + "] do not exist");
            }
        }
    }

    private Set<String> removePOGroups(ExecutionContext executionContext, Set<String> groups, String apiId) {
        Stream<GroupEntity> groupEntityStream = groupService.findByIds(groups).stream();

        if (apiId != null) {
            final MembershipEntity primaryOwner = membershipService.getPrimaryOwner(
                executionContext.getOrganizationId(),
                MembershipReferenceType.API,
                apiId
            );
            if (primaryOwner.getMemberType() == MembershipMemberType.GROUP) {
                // don't remove the primary owner group of this API.
                groupEntityStream =
                    groupEntityStream.filter(
                        group -> StringUtils.isEmpty(group.getApiPrimaryOwner()) || group.getId().equals(primaryOwner.getMemberId())
                    );
            } else {
                groupEntityStream = groupEntityStream.filter(group -> StringUtils.isEmpty(group.getApiPrimaryOwner()));
            }
        } else {
            groupEntityStream = groupEntityStream.filter(group -> StringUtils.isEmpty(group.getApiPrimaryOwner()));
        }

        return groupEntityStream.map(GroupEntity::getId).collect(Collectors.toSet());
    }

    @Override
    public ApiEntity create(ExecutionContext executionContext, final NewApiEntity newApiEntity, final String userId)
        throws ApiAlreadyExistsException {
        UpdateApiEntity apiEntity = new UpdateApiEntity();

        apiEntity.setName(newApiEntity.getName());
        apiEntity.setDescription(newApiEntity.getDescription());
        apiEntity.setVersion(newApiEntity.getVersion());
        apiEntity.setGraviteeDefinitionVersion(newApiEntity.getGraviteeDefinitionVersion());
        apiEntity.setFlows(newApiEntity.getFlows());
        apiEntity.setFlowMode(newApiEntity.getFlowMode());

        Set<String> groups = newApiEntity.getGroups();
        if (groups != null && !groups.isEmpty()) {
            checkGroupExistence(groups);
            groups = removePOGroups(executionContext, groups, null);
            newApiEntity.setGroups(groups);
        }
        apiEntity.setGroups(groups);

        Proxy proxy = new Proxy();
        proxy.setVirtualHosts(singletonList(new VirtualHost(newApiEntity.getContextPath())));
        EndpointGroup group = new EndpointGroup();
        group.setName("default-group");

        String[] endpoints = null;
        if (newApiEntity.getEndpoint() != null) {
            endpoints = newApiEntity.getEndpoint().split(ENDPOINTS_DELIMITER);
        }

        if (endpoints == null) {
            group.setEndpoints(singleton(new Endpoint("default", null)));
        } else if (endpoints.length == 1) {
            group.setEndpoints(singleton(new Endpoint("default", endpoints[0])));
        } else {
            group.setEndpoints(new HashSet<>());
            for (int i = 0; i < endpoints.length; i++) {
                group.getEndpoints().add(new Endpoint("server" + (i + 1), endpoints[i]));
            }
        }
        proxy.setGroups(singleton(group));
        apiEntity.setProxy(proxy);

        final List<String> declaredPaths = newApiEntity.getPaths() != null ? newApiEntity.getPaths() : new ArrayList<>();
        if (!declaredPaths.contains("/")) {
            declaredPaths.add(0, "/");
        }

        apiEntity.setPathMappings(new HashSet<>(declaredPaths));

        return createFromUpdateApiEntity(executionContext, apiEntity, userId, null);
    }

    @Override
    public ApiEntity createWithApiDefinition(ExecutionContext executionContext, UpdateApiEntity api, String userId, JsonNode apiDefinition)
        throws ApiAlreadyExistsException {
        try {
            LOGGER.debug("Create {} for user {}", api, userId);

            String apiId = apiDefinition != null && apiDefinition.has("id") ? apiDefinition.get("id").asText() : null;
            String id = apiId != null && UUID.fromString(apiId) != null ? apiId : UuidString.generateRandom();

            Optional<Api> checkApi = apiRepository.findById(id);
            if (checkApi.isPresent()) {
                throw new ApiAlreadyExistsException(id);
            }

            // if user changes sharding tags, then check if he is allowed to do it
            checkShardingTags(api, null, executionContext);

            // format context-path and check if context path is unique
            final Collection<VirtualHost> sanitizedVirtualHosts = virtualHostService.sanitizeAndValidate(
                executionContext,
                api.getProxy().getVirtualHosts()
            );
            api.getProxy().setVirtualHosts(new ArrayList<>(sanitizedVirtualHosts));

            // check endpoints configuration
            checkEndpointsConfiguration(api);

            // check HC inheritance
            checkHealthcheckInheritance(api);

            api.getProxy().setLogging(loggingValidationService.validateAndSanitize(executionContext, api.getProxy().getLogging()));

            // check if there is regex errors in plaintext fields
            validateRegexfields(api);

            // check policy configurations.
            checkPolicyConfigurations(api);

            // check policy configurations.
            checkResourceConfigurations(api);

            // check primary owner
            PrimaryOwnerEntity primaryOwner = findPrimaryOwner(executionContext, apiDefinition, userId);

            if (apiDefinition != null) {
                apiDefinition = ((ObjectNode) apiDefinition).put("id", id);
            }
            if (api.getExecutionMode() == null) {
                api.setExecutionMode(jupiterModeService.getExecutionModeFor(apiDefinition));
            }

            Api repoApi = convert(executionContext, id, api, apiDefinition != null ? apiDefinition.toString() : null);

            repoApi.setId(id);
            repoApi.setEnvironmentId(executionContext.getEnvironmentId());
            // Set date fields
            repoApi.setCreatedAt(new Date());
            repoApi.setUpdatedAt(repoApi.getCreatedAt());

            // Set definition context
            DefinitionContext definitionContext = new DefinitionContext();
            if (apiDefinition != null && apiDefinition.hasNonNull(API_DEFINITION_CONTET_FIELD)) {
                JsonNode definitionContextNode = apiDefinition.get(API_DEFINITION_CONTET_FIELD);
                String origin = definitionContextNode.get(API_DEFINITION_CONTEXT_FIELD_ORIGIN).asText();
                String mode = definitionContextNode.get(API_DEFINITION_CONTEXT_FIELD_MODE).asText();
                definitionContext = new DefinitionContext(origin, mode);
            }
            repoApi.setOrigin(definitionContext.getOrigin());
            repoApi.setMode(definitionContext.getMode());

            if (DefinitionContext.isKubernetes(repoApi.getOrigin())) {
                // Be sure that api is always marked as STARTED when managed by k8s.
                repoApi.setLifecycleState(LifecycleState.STARTED);

                // Set the api lifecycle state if defined or set it to CREATED by default.
                repoApi.setApiLifecycleState(
                    api.getLifecycleState() != null ? ApiLifecycleState.valueOf(api.getLifecycleState().name()) : ApiLifecycleState.CREATED
                );
            } else {
                // Be sure that lifecycle is set to STOPPED
                repoApi.setLifecycleState(LifecycleState.STOPPED);
                repoApi.setApiLifecycleState(ApiLifecycleState.CREATED);
            }

            // Make sure visibility is PRIVATE by default if not set.
            repoApi.setVisibility(api.getVisibility() == null ? Visibility.PRIVATE : Visibility.valueOf(api.getVisibility().toString()));

            // Add Default groups
            Set<String> defaultGroups = groupService
                .findByEvent(executionContext.getEnvironmentId(), GroupEvent.API_CREATE)
                .stream()
                .map(GroupEntity::getId)
                .collect(toSet());
            if (repoApi.getGroups() == null) {
                repoApi.setGroups(defaultGroups.isEmpty() ? null : defaultGroups);
            } else {
                repoApi.getGroups().addAll(defaultGroups);
            }

            // if po is a group, add it as a member of the API
            if (ApiPrimaryOwnerMode.GROUP.name().equals(primaryOwner.getType())) {
                if (repoApi.getGroups() == null) {
                    repoApi.setGroups(new HashSet<>());
                }
                repoApi.getGroups().add(primaryOwner.getId());
            }

            if (parameterService.findAsBoolean(executionContext, Key.API_REVIEW_ENABLED, ParameterReferenceType.ENVIRONMENT)) {
                workflowService.create(WorkflowReferenceType.API, id, REVIEW, userId, DRAFT, "");
            }

            Api createdApi = apiRepository.create(repoApi);

            // Audit
            auditService.createApiAuditLog(
                executionContext,
                createdApi.getId(),
                Collections.emptyMap(),
                API_CREATED,
                createdApi.getCreatedAt(),
                null,
                createdApi
            );

            // Add the primary owner of the newly created API
            membershipService.addRoleToMemberOnReference(
                executionContext,
                new MembershipService.MembershipReference(MembershipReferenceType.API, createdApi.getId()),
                new MembershipService.MembershipMember(primaryOwner.getId(), null, MembershipMemberType.valueOf(primaryOwner.getType())),
                new MembershipService.MembershipRole(RoleScope.API, SystemRole.PRIMARY_OWNER.name())
            );

            // create the default mail notification
            final String emailMetadataValue = "${(api.primaryOwner.email)!''}";

            GenericNotificationConfigEntity notificationConfigEntity = new GenericNotificationConfigEntity();
            notificationConfigEntity.setName("Default Mail Notifications");
            notificationConfigEntity.setReferenceType(HookScope.API.name());
            notificationConfigEntity.setReferenceId(createdApi.getId());
            notificationConfigEntity.setHooks(Arrays.stream(ApiHook.values()).map(Enum::name).collect(toList()));
            notificationConfigEntity.setNotifier(NotifierServiceImpl.DEFAULT_EMAIL_NOTIFIER_ID);
            notificationConfigEntity.setConfig(emailMetadataValue);
            genericNotificationConfigService.create(notificationConfigEntity);

            // create the default mail support metadata
            NewApiMetadataEntity newApiMetadataEntity = new NewApiMetadataEntity();
            newApiMetadataEntity.setFormat(MetadataFormat.MAIL);
            newApiMetadataEntity.setName(DefaultMetadataUpgrader.METADATA_EMAIL_SUPPORT_KEY);
            newApiMetadataEntity.setDefaultValue(emailMetadataValue);
            newApiMetadataEntity.setValue(emailMetadataValue);
            newApiMetadataEntity.setApiId(createdApi.getId());
            apiMetadataService.create(executionContext, newApiMetadataEntity);

            // create the API flows
            flowService.save(FlowReferenceType.API, createdApi.getId(), api.getFlows());

            //TODO add membership log
            ApiEntity apiEntity = convert(executionContext, createdApi, primaryOwner, null);
            GenericApiEntity apiWithMetadata = apiMetadataService.fetchMetadataForApi(executionContext, apiEntity);

            searchEngineService.index(executionContext, apiWithMetadata, false);
            return apiEntity;
        } catch (TechnicalException | IllegalStateException ex) {
            LOGGER.error("An error occurs while trying to create {} for user {}", api, userId, ex);
            throw new TechnicalManagementException("An error occurs while trying create " + api + " for user " + userId, ex);
        }
    }

    private ApiEntity createFromUpdateApiEntity(
        ExecutionContext executionContext,
        final UpdateApiEntity apiEntity,
        final String userId,
        final ImportSwaggerDescriptorEntity swaggerDescriptor
    ) {
        final ApiEntity createdApi = this.createWithApiDefinition(executionContext, apiEntity, userId, null);
        pageService.createAsideFolder(executionContext, createdApi.getId());
        pageService.createOrUpdateSwaggerPage(executionContext, createdApi.getId(), swaggerDescriptor, true);
        return createdApi;
    }

    public PrimaryOwnerEntity findPrimaryOwner(ExecutionContext executionContext, JsonNode apiDefinition, String userId) {
        PrimaryOwnerEntity primaryOwnerFromDefinition = findPrimaryOwnerFromApiDefinition(apiDefinition);
        return primaryOwnerService.getPrimaryOwner(executionContext, userId, primaryOwnerFromDefinition);
    }

    private PrimaryOwnerEntity findPrimaryOwnerFromApiDefinition(JsonNode apiDefinition) {
        PrimaryOwnerEntity primaryOwnerEntity = null;
        if (apiDefinition != null && apiDefinition.has("primaryOwner")) {
            try {
                primaryOwnerEntity = objectMapper.readValue(apiDefinition.get("primaryOwner").toString(), PrimaryOwnerEntity.class);
            } catch (JsonProcessingException e) {
                LOGGER.warn("Cannot parse primary owner from definition, continue with current user", e);
            }
        }
        return primaryOwnerEntity;
    }

    private void checkEndpointsConfiguration(UpdateApiEntity api) {
        if (api.getProxy() != null && api.getProxy().getGroups() != null) {
            for (EndpointGroup group : api.getProxy().getGroups()) {
                assertEndpointNameNotContainsInvalidCharacters(group.getName());
                if (group.getEndpoints() != null) {
                    for (Endpoint endpoint : group.getEndpoints()) {
                        assertEndpointNameNotContainsInvalidCharacters(endpoint.getName());
                        endpoint.setConfiguration(
                            connectorService.validateConnectorConfiguration(endpoint.getType(), endpoint.getConfiguration())
                        );
                    }
                }
            }
        }
    }

    private void checkEndpointsExists(UpdateApiEntity api) {
        if (api.getProxy().getGroups() == null || api.getProxy().getGroups().isEmpty()) {
            throw new EndpointMissingException();
        }

        EndpointGroup endpointGroup = api.getProxy().getGroups().iterator().next();
        //Is service discovery enabled ?
        EndpointDiscoveryService endpointDiscoveryService = endpointGroup.getServices() == null
            ? null
            : endpointGroup.getServices().get(EndpointDiscoveryService.class);
        if (
            (endpointDiscoveryService == null || !endpointDiscoveryService.isEnabled()) &&
            (endpointGroup.getEndpoints() == null || endpointGroup.getEndpoints().isEmpty())
        ) {
            throw new EndpointMissingException();
        }
    }

    private void validateHealtcheckSchedule(UpdateApiEntity api) {
        if (api.getServices() != null) {
            HealthCheckService healthCheckService = api.getServices().get(HealthCheckService.class);
            if (healthCheckService != null) {
                String schedule = healthCheckService.getSchedule();
                if (schedule != null) {
                    try {
                        new CronTrigger(schedule);
                    } catch (IllegalArgumentException e) {
                        throw new InvalidDataException(e);
                    }
                }
            }
        }
    }

    private void checkHealthcheckInheritance(UpdateApiEntity api) {
        boolean inherit = false;

        if (api.getProxy() != null && api.getProxy().getGroups() != null) {
            for (EndpointGroup group : api.getProxy().getGroups()) {
                if (group.getEndpoints() != null) {
                    for (Endpoint endpoint : group.getEndpoints()) {
                        if (isHttpEndpoint(endpoint) && endpoint.getHealthCheck() != null && endpoint.getHealthCheck().isInherit()) {
                            inherit = true;
                            break;
                        }
                    }
                }
            }
        }

        if (inherit) {
            //if endpoints are set to inherit HC configuration, this configuration must exists.
            boolean hcServiceExists = false;
            if (api.getServices() != null) {
                HealthCheckService healthCheckService = api.getServices().get(HealthCheckService.class);
                hcServiceExists = healthCheckService != null;
            }

            if (!hcServiceExists) {
                throw new HealthcheckInheritanceException();
            }
        }
    }

    // FIXME: https://github.com/gravitee-io/issues/issues/6437
    private boolean isHttpEndpoint(Endpoint endpoint) {
        return "grpc".equalsIgnoreCase(endpoint.getType()) || "http".equalsIgnoreCase(endpoint.getType());
    }

    private void assertEndpointNameNotContainsInvalidCharacters(String name) {
        if (name != null && name.contains(":")) {
            throw new EndpointNameInvalidException(name);
        }
    }

    @Override
    public ApiEntity findById(ExecutionContext executionContext, String apiId) {
        final Api api = this.findApiById(executionContext, apiId);
        ApiEntity apiEntity = convert(executionContext, api, getPrimaryOwner(executionContext, api), null);

        // Compute entrypoints
        List<ApiEntrypointEntity> apiEntrypoints = apiEntrypointService.getApiEntrypoints(executionContext, apiEntity);
        apiEntity.setEntrypoints(apiEntrypoints);

        return apiEntity;
    }

    @Override
    public Optional<ApiEntity> findByEnvironmentIdAndCrossId(String environment, String crossId) {
        try {
            return apiRepository.findByEnvironmentIdAndCrossId(environment, crossId).map(api -> apiConverter.toApiEntity(api, null));
        } catch (TechnicalException e) {
            throw new TechnicalManagementException(
                "An error occurred while finding API by environment " + environment + " and crossId " + crossId,
                e
            );
        }
    }

    private PrimaryOwnerEntity getPrimaryOwner(ExecutionContext executionContext, Api api) throws TechnicalManagementException {
        return primaryOwnerService.getPrimaryOwner(executionContext, api.getId());
    }

    @Override
    public Map<String, Object> findByIdAsMap(String id) throws TechnicalException {
        Api api = apiRepository.findById(id).orElseThrow(() -> new ApiNotFoundException(id));

        ExecutionContext executionContext = new ExecutionContext(environmentService.findById(api.getEnvironmentId()));

        ApiEntity apiEntity = convert(executionContext, api, getPrimaryOwner(executionContext, api), null);

        Map<String, Object> dataAsMap = objectMapper.convertValue(apiEntity, Map.class);
        dataAsMap.put("id", id);
        dataAsMap.put("primaryOwner", objectMapper.convertValue(apiEntity.getPrimaryOwner(), Map.class));
        dataAsMap.remove("picture");
        dataAsMap.remove("proxy");
        dataAsMap.remove("paths");
        dataAsMap.remove("properties");
        dataAsMap.remove("services");
        dataAsMap.remove("resources");
        dataAsMap.remove("response_templates");
        dataAsMap.remove("path_mappings");

        final List<ApiMetadataEntity> metadataList = apiMetadataService.findAllByApi(id);
        final Map<String, String> mapMetadata = new HashMap<>(metadataList.size());
        metadataList.forEach(m -> mapMetadata.put(m.getKey(), m.getValue() == null ? m.getDefaultValue() : m.getValue()));
        dataAsMap.put("metadata", objectMapper.convertValue(mapMetadata, Map.class));

        return dataAsMap;
    }

    @Override
    public Set<ApiEntity> findByVisibility(ExecutionContext executionContext, io.gravitee.rest.api.model.Visibility visibility) {
        LOGGER.debug("Find APIs by visibility {}", visibility);
        return new HashSet<>(
            convert(
                executionContext,
                apiRepository.search(
                    getDefaultApiCriteriaBuilder()
                        .environmentId(executionContext.getEnvironmentId())
                        .visibility(Visibility.valueOf(visibility.name()))
                        .build()
                )
            )
        );
    }

    @Override
    public Set<ApiEntity> findAllByEnvironment(final ExecutionContext executionContext) {
        LOGGER.debug("Find all APIs for environment {}", executionContext.getEnvironmentId());
        return new HashSet<>(
            convert(
                executionContext,
                apiRepository.search(getDefaultApiCriteriaBuilder().environmentId(executionContext.getEnvironmentId()).build())
            )
        );
    }

    @Override
    public Set<ApiEntity> findAllLightByEnvironment(ExecutionContext executionContext, boolean excludeDefinition) {
        LOGGER.debug("Find all APIs without some fields (definition, picture...) for environment {}", executionContext.getEnvironmentId());
        final ApiFieldExclusionFilter.Builder exclusionFilterBuilder = new ApiFieldExclusionFilter.Builder().excludePicture();
        if (excludeDefinition) {
            exclusionFilterBuilder.excludeDefinition();
        }
        return new HashSet<>(
            convert(
                executionContext,
                apiRepository.search(
                    getDefaultApiCriteriaBuilder().environmentId(executionContext.getEnvironmentId()).build(),
                    exclusionFilterBuilder.build()
                )
            )
        );
    }

    @Override
    public Set<ApiEntity> findAllLight(ExecutionContext executionContext) {
        return findAllLightByEnvironment(executionContext, false);
    }

    @Override
    public Set<ApiEntity> findByUser(ExecutionContext executionContext, String userId, ApiQuery apiQuery, boolean portal) {
        return new HashSet<>(findByUser(executionContext, userId, apiQuery, null, null, portal).getContent());
    }

    @Override
    public Page<ApiEntity> findByUser(
        ExecutionContext executionContext,
        String userId,
        ApiQuery apiQuery,
        Sortable sortable,
        Pageable pageable,
        boolean portal
    ) {
        try {
            LOGGER.debug("Find APIs page by user {}", userId);

            Set<String> apiIds = apiAuthorizationService.findIdsByUser(executionContext, userId, apiQuery, sortable, portal);

            return loadPage(executionContext, apiIds, pageable);
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to find APIs for user {}", userId, ex);
            throw new TechnicalManagementException("An error occurs while trying to find APIs for user " + userId, ex);
        }
    }

    private Api findApiById(ExecutionContext executionContext, String apiId) {
        try {
            LOGGER.debug("Find API by ID: {}", apiId);

            Optional<Api> optApi = apiRepository.findById(apiId);

            if (executionContext.hasEnvironmentId()) {
                optApi = optApi.filter(result -> result.getEnvironmentId().equals(executionContext.getEnvironmentId()));
            }

            return optApi.orElseThrow(() -> new ApiNotFoundException(apiId));
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to find an API using its ID: {}", apiId, ex);
            throw new TechnicalManagementException("An error occurs while trying to find an API using its ID: " + apiId, ex);
        }
    }

    private Set merge(List originSet, Collection setToAdd) {
        if (originSet == null) {
            return merge(Collections.emptySet(), setToAdd);
        }
        return merge(new HashSet<>(originSet), setToAdd);
    }

    private Set merge(Set originSet, Collection setToAdd) {
        if (setToAdd != null && !setToAdd.isEmpty()) {
            if (originSet == null) {
                originSet = new HashSet();
            }
            originSet.addAll(setToAdd);
        }
        return originSet;
    }

    @Override
    public ApiEntity updateFromSwagger(
        ExecutionContext executionContext,
        String apiId,
        SwaggerApiEntity swaggerApiEntity,
        ImportSwaggerDescriptorEntity swaggerDescriptor
    ) {
        final ApiEntity apiEntityToUpdate = this.findById(executionContext, apiId);
        final UpdateApiEntity updateApiEntity = apiConverter.toUpdateApiEntity(apiEntityToUpdate);

        // Overwrite from swagger
        updateApiEntity.setVersion(swaggerApiEntity.getVersion());
        updateApiEntity.setName(swaggerApiEntity.getName());
        updateApiEntity.setDescription(swaggerApiEntity.getDescription());

        updateApiEntity.setCategories(merge(updateApiEntity.getCategories(), swaggerApiEntity.getCategories()));

        if (swaggerApiEntity.getProxy() != null) {
            Proxy proxy = updateApiEntity.getProxy();
            if (proxy == null) {
                proxy = new Proxy();
            }

            proxy.setGroups(merge(proxy.getGroups(), swaggerApiEntity.getProxy().getGroups()));

            List<VirtualHost> virtualHostsToAdd = swaggerApiEntity.getProxy().getVirtualHosts();
            if (virtualHostsToAdd != null && !virtualHostsToAdd.isEmpty()) {
                // Sanitize both current vHost and vHost to add to avoid duplicates
                virtualHostsToAdd = virtualHostsToAdd.stream().map(this.virtualHostService::sanitize).collect(toList());
                proxy.setVirtualHosts(
                    new ArrayList<>(
                        merge(proxy.getVirtualHosts().stream().map(this.virtualHostService::sanitize).collect(toSet()), virtualHostsToAdd)
                    )
                );
            }
            updateApiEntity.setProxy(proxy);
        }

        updateApiEntity.setGroups(merge(updateApiEntity.getGroups(), swaggerApiEntity.getGroups()));
        updateApiEntity.setLabels(new ArrayList<>(merge(updateApiEntity.getLabels(), swaggerApiEntity.getLabels())));
        if (swaggerApiEntity.getPicture() != null) {
            updateApiEntity.setPicture(swaggerApiEntity.getPicture());
        }
        updateApiEntity.setTags(merge(updateApiEntity.getTags(), swaggerApiEntity.getTags()));
        if (swaggerApiEntity.getVisibility() != null) {
            updateApiEntity.setVisibility(swaggerApiEntity.getVisibility());
        }

        if (swaggerApiEntity.getProperties() != null) {
            PropertiesEntity properties = updateApiEntity.getProperties();
            if (properties == null) {
                properties = new PropertiesEntity();
            }
            properties.setProperties(new ArrayList<>(merge(properties.getProperties(), swaggerApiEntity.getProperties().getProperties())));
            updateApiEntity.setProperties(properties);
        }

        // Overwrite from swagger, if asked
        if (swaggerDescriptor != null) {
            if (swaggerDescriptor.isWithPathMapping()) {
                updateApiEntity.setPathMappings(swaggerApiEntity.getPathMappings());
            }

            if (swaggerDescriptor.isWithPolicyPaths()) {
                if (DefinitionVersion.V2.getLabel().equals(updateApiEntity.getGraviteeDefinitionVersion())) {
                    updateApiEntity.setFlows(swaggerApiEntity.getFlows());
                } else {
                    updateApiEntity.setPaths(swaggerApiEntity.getPaths());
                }
            }
        }

        pageService.createOrUpdateSwaggerPage(executionContext, apiEntityToUpdate.getId(), swaggerDescriptor, false);

        final ApiEntity updatedApi = update(executionContext, apiId, updateApiEntity);

        if (swaggerApiEntity.getMetadata() != null && !swaggerApiEntity.getMetadata().isEmpty()) {
            swaggerApiEntity
                .getMetadata()
                .forEach(
                    data -> {
                        try {
                            final ApiMetadataEntity apiMetadataEntity = this.apiMetadataService.findByIdAndApi(data.getKey(), apiId);
                            UpdateApiMetadataEntity updateApiMetadataEntity = new UpdateApiMetadataEntity();
                            updateApiMetadataEntity.setApiId(apiId);
                            updateApiMetadataEntity.setFormat(data.getFormat());
                            updateApiMetadataEntity.setKey(apiMetadataEntity.getKey());
                            updateApiMetadataEntity.setName(data.getName());
                            updateApiMetadataEntity.setValue(data.getValue());
                            ApiMetadataEntity metadata = this.apiMetadataService.update(executionContext, updateApiMetadataEntity);
                            updatedApi.getMetadata().put(metadata.getKey(), metadata.getValue());
                        } catch (ApiMetadataNotFoundException amnfe) {
                            NewApiMetadataEntity newMD = new NewApiMetadataEntity();
                            newMD.setApiId(apiId);
                            newMD.setFormat(data.getFormat());
                            newMD.setName(data.getName());
                            newMD.setValue(data.getValue());
                            ApiMetadataEntity metadata = this.apiMetadataService.create(executionContext, newMD);
                            updatedApi.getMetadata().put(metadata.getKey(), metadata.getValue());
                        }
                    }
                );
        }

        searchEngineService.index(executionContext, updatedApi, false);

        return updatedApi;
    }

    @Override
    public ApiEntity update(ExecutionContext executionContext, String apiId, UpdateApiEntity updateApiEntity) {
        return update(executionContext, apiId, updateApiEntity, false);
    }

    @Override
    public ApiEntity update(ExecutionContext executionContext, String apiId, UpdateApiEntity updateApiEntity, boolean checkPlans) {
        try {
            LOGGER.debug("Update API {}", apiId);

            Api apiToUpdate = apiRepository.findById(apiId).orElseThrow(() -> new ApiNotFoundException(apiId));

            // check if entrypoints are unique
            final Collection<VirtualHost> sanitizedVirtualHosts = virtualHostService.sanitizeAndValidate(
                executionContext,
                updateApiEntity.getProxy().getVirtualHosts(),
                apiId
            );
            updateApiEntity.getProxy().setVirtualHosts(new ArrayList<>(sanitizedVirtualHosts));

            // check endpoints presence
            checkEndpointsExists(updateApiEntity);

            // check endpoints configuration
            checkEndpointsConfiguration(updateApiEntity);

            // check HC inheritance
            checkHealthcheckInheritance(updateApiEntity);

            // validate HC cron schedule
            validateHealtcheckSchedule(updateApiEntity);

            // check CORS Allow-origin format
            updateApiEntity.getProxy().setCors(corsValidationService.validateAndSanitize(updateApiEntity.getProxy().getCors()));

            updateApiEntity
                .getProxy()
                .setLogging(loggingValidationService.validateAndSanitize(executionContext, updateApiEntity.getProxy().getLogging()));

            // check if there is regex errors in plaintext fields
            validateRegexfields(updateApiEntity);

            // check policy configurations.
            checkPolicyConfigurations(updateApiEntity);

            // check resource configurations.
            checkResourceConfigurations(updateApiEntity);

            final ApiEntity apiToCheck = convert(executionContext, apiToUpdate);

            // if user changes definition version, then check if he is allowed to do it
            checkDefinitionVersion(updateApiEntity, apiToCheck);

            // if user changes sharding tags, then check if he is allowed to do it
            checkShardingTags(updateApiEntity, apiToCheck, executionContext);

            // if lifecycle state not provided, set the saved one
            if (updateApiEntity.getLifecycleState() == null) {
                updateApiEntity.setLifecycleState(apiToCheck.getLifecycleState());
            }

            // check lifecycle state
            checkLifecycleState(updateApiEntity, apiToCheck);

            Set<String> groups = updateApiEntity.getGroups();
            if (groups != null && !groups.isEmpty()) {
                // check the existence of groups
                checkGroupExistence(groups);

                // remove PO group if exists
                groups = removePOGroups(executionContext, groups, apiId);
                updateApiEntity.setGroups(groups);
            }

            // add a default path, if version is v1
            if (
                Objects.equals(updateApiEntity.getGraviteeDefinitionVersion(), DefinitionVersion.V1.getLabel()) &&
                (updateApiEntity.getPaths() == null || updateApiEntity.getPaths().isEmpty())
            ) {
                updateApiEntity.setPaths(singletonMap("/", new ArrayList<>()));
            }

            if (updateApiEntity.getPlans() == null) {
                updateApiEntity.setPlans(new HashSet<>());
            } else if (checkPlans) {
                Set<PlanEntity> existingPlans = apiToCheck.getPlans();
                Map<String, PlanStatus> planStatuses = new HashMap<>();
                if (existingPlans != null && !existingPlans.isEmpty()) {
                    planStatuses.putAll(existingPlans.stream().collect(toMap(PlanEntity::getId, PlanEntity::getStatus)));
                }

                updateApiEntity
                    .getPlans()
                    .forEach(
                        planToUpdate -> {
                            if (
                                !planStatuses.containsKey(planToUpdate.getId()) ||
                                (
                                    planStatuses.containsKey(planToUpdate.getId()) &&
                                    planStatuses.get(planToUpdate.getId()) == PlanStatus.CLOSED &&
                                    planStatuses.get(planToUpdate.getId()) != planToUpdate.getStatus()
                                )
                            ) {
                                throw new InvalidDataException("Invalid status for plan '" + planToUpdate.getName() + "'");
                            }
                        }
                    );
            }

            // encrypt API properties
            encryptProperties(updateApiEntity.getPropertyList());

            if (io.gravitee.rest.api.model.api.ApiLifecycleState.DEPRECATED.equals(updateApiEntity.getLifecycleState())) {
                planService
                    .findByApi(executionContext, apiId)
                    .forEach(
                        plan -> {
                            if (PlanStatus.PUBLISHED.equals(plan.getStatus()) || PlanStatus.STAGING.equals(plan.getStatus())) {
                                planService.deprecate(executionContext, plan.getId(), true);
                                updateApiEntity
                                    .getPlans()
                                    .stream()
                                    .filter(p -> p.getId().equals(plan.getId()))
                                    .forEach(p -> p.setStatus(PlanStatus.DEPRECATED));
                            }
                        }
                    );
            }

            Api api = convert(executionContext, apiId, updateApiEntity, apiToUpdate.getDefinition());

            api.setUpdatedAt(new Date());

            // Copy fields from existing values
            api.setEnvironmentId(apiToUpdate.getEnvironmentId());
            api.setDeployedAt(apiToUpdate.getDeployedAt());
            api.setCreatedAt(apiToUpdate.getCreatedAt());
            api.setOrigin(apiToUpdate.getOrigin());
            api.setMode(apiToUpdate.getMode());

            if (DefinitionContext.isKubernetes(api.getOrigin())) {
                // Be sure that api is started when managed by k8s.
                api.setLifecycleState(LifecycleState.STARTED);
                if (updateApiEntity.getLifecycleState() != null) {
                    api.setApiLifecycleState(ApiLifecycleState.valueOf(updateApiEntity.getLifecycleState().name()));
                }
            } else {
                api.setLifecycleState(apiToUpdate.getLifecycleState());
            }

            if (updateApiEntity.getCrossId() == null) {
                api.setCrossId(apiToUpdate.getCrossId());
            }

            // If no new picture and the current picture url is not the default one, keep the current picture
            if (
                updateApiEntity.getPicture() == null &&
                updateApiEntity.getPictureUrl() != null &&
                updateApiEntity.getPictureUrl().indexOf("?hash") > 0
            ) {
                api.setPicture(apiToUpdate.getPicture());
            }
            if (
                updateApiEntity.getBackground() == null &&
                updateApiEntity.getBackgroundUrl() != null &&
                updateApiEntity.getBackgroundUrl().indexOf("?hash") > 0
            ) {
                api.setBackground(apiToUpdate.getBackground());
            }
            if (updateApiEntity.getGroups() == null) {
                api.setGroups(apiToUpdate.getGroups());
            }
            if (updateApiEntity.getLabels() == null && apiToUpdate.getLabels() != null) {
                api.setLabels(new ArrayList<>(new HashSet<>(apiToUpdate.getLabels())));
            }
            if (updateApiEntity.getCategories() == null) {
                api.setCategories(apiToUpdate.getCategories());
            }

            if (ApiLifecycleState.DEPRECATED.equals(api.getApiLifecycleState())) {
                apiNotificationService.triggerDeprecatedNotification(executionContext, apiToCheck);
            }

            Api updatedApi = apiRepository.update(api);

            // update API flows
            flowService.save(FlowReferenceType.API, api.getId(), updateApiEntity.getFlows());

            // update API plans
            updateApiEntity
                .getPlans()
                .forEach(
                    plan -> {
                        plan.setApi(api.getId());
                        planService.createOrUpdatePlan(executionContext, plan);
                    }
                );

            // Audit
            auditService.createApiAuditLog(
                executionContext,
                updatedApi.getId(),
                Collections.emptyMap(),
                API_UPDATED,
                updatedApi.getUpdatedAt(),
                apiToUpdate,
                updatedApi
            );

            if (parameterService.findAsBoolean(executionContext, Key.LOGGING_AUDIT_TRAIL_ENABLED, ParameterReferenceType.ENVIRONMENT)) {
                // Audit API logging if option is enabled
                auditApiLogging(executionContext, apiToUpdate, updatedApi);
            }

            final List<CategoryEntity> categories = categoryService.findAll(executionContext.getEnvironmentId());
            PrimaryOwnerEntity primaryOwner = getPrimaryOwner(executionContext, updatedApi);
            ApiEntity apiEntity = convert(executionContext, updatedApi, primaryOwner, categories);
            GenericApiEntity apiWithMetadata = apiMetadataService.fetchMetadataForApi(executionContext, apiEntity);

            apiNotificationService.triggerUpdateNotification(executionContext, apiEntity);

            searchEngineService.index(executionContext, apiWithMetadata, false);

            return apiEntity;
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to update API {}", apiId, ex);
            throw new TechnicalManagementException("An error occurs while trying to update API " + apiId, ex);
        }
    }

    private String buildApiDefinition(String apiId, String apiDefinition, UpdateApiEntity updateApiEntity) {
        try {
            io.gravitee.definition.model.Api updateApiDefinition;
            if (apiDefinition == null || apiDefinition.isEmpty()) {
                updateApiDefinition = new io.gravitee.definition.model.Api();
                updateApiDefinition.setDefinitionVersion(DefinitionVersion.valueOfLabel(updateApiEntity.getGraviteeDefinitionVersion()));
            } else {
                updateApiDefinition = objectMapper.readValue(apiDefinition, io.gravitee.definition.model.Api.class);

                // clear plans and flows as they are stored in flows table ; avoid useless duplicated storage in api definition
                updateApiDefinition.setPlans(Collections.emptyList());
                updateApiDefinition.setFlows(Collections.emptyList());
            }
            updateApiDefinition.setId(apiId);
            updateApiDefinition.setName(updateApiEntity.getName());
            updateApiDefinition.setVersion(updateApiEntity.getVersion());
            updateApiDefinition.setProxy(updateApiEntity.getProxy());

            if (updateApiEntity.getExecutionMode() != null) {
                updateApiDefinition.setExecutionMode(updateApiEntity.getExecutionMode());
            }

            if (StringUtils.isNotEmpty(updateApiEntity.getGraviteeDefinitionVersion())) {
                updateApiDefinition.setDefinitionVersion(DefinitionVersion.valueOfLabel(updateApiEntity.getGraviteeDefinitionVersion()));
            }

            if (updateApiEntity.getFlowMode() != null) {
                updateApiDefinition.setFlowMode(updateApiEntity.getFlowMode());
            }

            if (updateApiEntity.getPaths() != null) {
                updateApiDefinition.setPaths(updateApiEntity.getPaths());
            }
            if (updateApiEntity.getPathMappings() != null) {
                updateApiDefinition.setPathMappings(
                    updateApiEntity
                        .getPathMappings()
                        .stream()
                        .collect(toMap(pathMapping -> pathMapping, pathMapping -> Pattern.compile("")))
                );
            }

            updateApiDefinition.setServices(updateApiEntity.getServices());
            updateApiDefinition.setResources(updateApiEntity.getResources());
            if (updateApiEntity.getProperties() != null) {
                updateApiDefinition.setProperties(updateApiEntity.getProperties().toDefinition());
            }
            updateApiDefinition.setTags(updateApiEntity.getTags());

            updateApiDefinition.setResponseTemplates(updateApiEntity.getResponseTemplates());

            return objectMapper.writeValueAsString(updateApiDefinition);
        } catch (JsonProcessingException jse) {
            LOGGER.error("Unexpected error while generating API definition", jse);
            throw new TechnicalManagementException("An error occurs while trying to parse API definition " + jse);
        }
    }

    private void checkDefinitionVersion(final UpdateApiEntity updateApiEntity, final ApiEntity existingAPI) {
        if (existingAPI != null && updateApiEntity.getGraviteeDefinitionVersion() != null) {
            DefinitionVersion updateDefinitionVersion = DefinitionVersion.valueOfLabel(updateApiEntity.getGraviteeDefinitionVersion());
            if (updateDefinitionVersion == null) {
                throw new InvalidDataException("Invalid definition version for api '" + existingAPI.getId() + "'");
            }
            DefinitionVersion existingDefinitionVersion = DefinitionVersion.valueOfLabel(existingAPI.getGraviteeDefinitionVersion());
            if (updateDefinitionVersion.asInteger() < existingDefinitionVersion.asInteger()) {
                throw new DefinitionVersionException();
            }
        }
    }

    private void checkShardingTags(final UpdateApiEntity updateApiEntity, final ApiEntity existingAPI, ExecutionContext executionContext) {
        final Set<String> tagsToUpdate = updateApiEntity.getTags() == null ? new HashSet<>() : updateApiEntity.getTags();
        final Set<String> updatedTags;
        if (existingAPI == null) {
            updatedTags = tagsToUpdate;
        } else {
            final Set<String> existingAPITags = existingAPI.getTags() == null ? new HashSet<>() : existingAPI.getTags();
            updatedTags = existingAPITags.stream().filter(tag -> !tagsToUpdate.contains(tag)).collect(toSet());
            updatedTags.addAll(tagsToUpdate.stream().filter(tag -> !existingAPITags.contains(tag)).collect(toSet()));
        }
        if (updatedTags != null && !updatedTags.isEmpty()) {
            final Set<String> userTags = tagService.findByUser(
                getAuthenticatedUsername(),
                executionContext.getOrganizationId(),
                TagReferenceType.ORGANIZATION
            );
            if (!userTags.containsAll(updatedTags)) {
                final String[] notAllowedTags = updatedTags.stream().filter(tag -> !userTags.contains(tag)).toArray(String[]::new);
                throw new TagNotAllowedException(notAllowedTags);
            }
        }
    }

    private void checkResourceConfigurations(final UpdateApiEntity updateApiEntity) {
        List<Resource> resources = updateApiEntity.getResources();
        if (resources != null) {
            resources.stream().filter(Resource::isEnabled).forEach(resource -> resourceService.validateResourceConfiguration(resource));
        }
    }

    private void checkPolicyConfigurations(final UpdateApiEntity updateApiEntity) {
        checkPolicyConfigurations(updateApiEntity.getPaths(), updateApiEntity.getFlows(), updateApiEntity.getPlans());
    }

    public void checkPolicyConfigurations(Map<String, List<Rule>> paths, List<Flow> flows, Set<PlanEntity> plans) {
        checkPathsPolicyConfiguration(paths);
        checkFlowsPolicyConfiguration(flows);

        if (plans != null) {
            plans
                .stream()
                .forEach(
                    plan -> {
                        checkPathsPolicyConfiguration(plan.getPaths());
                        checkFlowsPolicyConfiguration(plan.getFlows());
                    }
                );
        }
    }

    private void checkPathsPolicyConfiguration(Map<String, List<Rule>> paths) {
        if (paths != null) {
            paths.forEach(
                (s, rules) ->
                    rules
                        .stream()
                        .filter(Rule::isEnabled)
                        .map(Rule::getPolicy)
                        .forEach(policy -> policyService.validatePolicyConfiguration(policy))
            );
        }
    }

    private void checkFlowsPolicyConfiguration(List<Flow> flows) {
        if (flows != null) {
            flows
                .stream()
                .filter(flow -> flow.getPre() != null)
                .forEach(
                    flow -> flow.getPre().stream().filter(Step::isEnabled).forEach(step -> policyService.validatePolicyConfiguration(step))
                );

            flows
                .stream()
                .filter(flow -> flow.getPost() != null)
                .forEach(
                    flow -> flow.getPost().stream().filter(Step::isEnabled).forEach(step -> policyService.validatePolicyConfiguration(step))
                );
        }
    }

    private void validateRegexfields(final UpdateApiEntity updateApiEntity) {
        // validate regex on paths
        if (updateApiEntity.getPaths() != null) {
            updateApiEntity
                .getPaths()
                .forEach(
                    (path, v) -> {
                        try {
                            Pattern.compile(path);
                        } catch (java.util.regex.PatternSyntaxException pse) {
                            LOGGER.error("An error occurs while trying to parse the path {}", path, pse);
                            throw new TechnicalManagementException("An error occurs while trying to parse the path " + path, pse);
                        }
                    }
                );
        }

        // validate regex on pathMappings
        if (updateApiEntity.getPathMappings() != null) {
            updateApiEntity
                .getPathMappings()
                .forEach(
                    pathMapping -> {
                        try {
                            Pattern.compile(pathMapping);
                        } catch (java.util.regex.PatternSyntaxException pse) {
                            LOGGER.error("An error occurs while trying to parse the path mapping {}", pathMapping, pse);
                            throw new TechnicalManagementException(
                                "An error occurs while trying to parse the path mapping" + pathMapping,
                                pse
                            );
                        }
                    }
                );
        }
    }

    private void checkLifecycleState(final UpdateApiEntity updateApiEntity, final ApiEntity existingAPI) {
        if (io.gravitee.rest.api.model.api.ApiLifecycleState.DEPRECATED.equals(existingAPI.getLifecycleState())) {
            throw new LifecycleStateChangeNotAllowedException(updateApiEntity.getLifecycleState().name());
        }
        if (existingAPI.getLifecycleState().name().equals(updateApiEntity.getLifecycleState().name())) {
            return;
        }
        if (io.gravitee.rest.api.model.api.ApiLifecycleState.ARCHIVED.equals(existingAPI.getLifecycleState())) {
            if (!io.gravitee.rest.api.model.api.ApiLifecycleState.ARCHIVED.equals(updateApiEntity.getLifecycleState())) {
                throw new LifecycleStateChangeNotAllowedException(updateApiEntity.getLifecycleState().name());
            }
        } else if (io.gravitee.rest.api.model.api.ApiLifecycleState.UNPUBLISHED.equals(existingAPI.getLifecycleState())) {
            if (io.gravitee.rest.api.model.api.ApiLifecycleState.CREATED.equals(updateApiEntity.getLifecycleState())) {
                throw new LifecycleStateChangeNotAllowedException(updateApiEntity.getLifecycleState().name());
            }
        } else if (io.gravitee.rest.api.model.api.ApiLifecycleState.CREATED.equals(existingAPI.getLifecycleState())) {
            if (WorkflowState.IN_REVIEW.equals(existingAPI.getWorkflowState())) {
                throw new LifecycleStateChangeNotAllowedException(updateApiEntity.getLifecycleState().name());
            }
        }
    }

    @Override
    public void delete(ExecutionContext executionContext, String apiId, boolean closePlans) {
        try {
            LOGGER.debug("Delete API {}", apiId);

            Api api = apiRepository.findById(apiId).orElseThrow(() -> new ApiNotFoundException(apiId));
            if (DefinitionContext.isManagement(api.getOrigin()) && api.getLifecycleState() == LifecycleState.STARTED) {
                throw new ApiRunningStateException(apiId);
            }

            Set<PlanEntity> plans = planService.findByApi(executionContext, apiId);
            if (closePlans) {
                plans =
                    plans
                        .stream()
                        .filter(plan -> plan.getStatus() != PlanStatus.CLOSED)
                        .map(plan -> planService.close(executionContext, plan.getId()))
                        .collect(Collectors.toSet());
            }

            Set<String> plansNotClosed = plans
                .stream()
                .filter(plan -> plan.getStatus() == PlanStatus.PUBLISHED)
                .map(PlanEntity::getName)
                .collect(toSet());

            if (!plansNotClosed.isEmpty()) {
                throw new ApiNotDeletableException(plansNotClosed);
            }

            Collection<SubscriptionEntity> subscriptions = subscriptionService.findByApi(executionContext, apiId);
            subscriptions.forEach(sub -> subscriptionService.delete(executionContext, sub.getId()));

            // Delete plans
            plans.forEach(plan -> planService.delete(executionContext, plan.getId()));

            // Delete flows
            flowService.save(FlowReferenceType.API, apiId, null);

            // Delete events
            final EventQuery query = new EventQuery();
            query.setApi(apiId);
            eventService.search(executionContext, query).forEach(event -> eventService.delete(event.getId()));

            // https://github.com/gravitee-io/issues/issues/4130
            // Ensure we are sending a last UNPUBLISH_API event because the gateway couldn't be aware that the API (and
            // all its relative events) have been deleted.
            Map<String, String> properties = new HashMap<>(2);
            properties.put(Event.EventProperties.API_ID.getValue(), apiId);
            if (getAuthenticatedUser() != null) {
                properties.put(Event.EventProperties.USER.getValue(), getAuthenticatedUser().getUsername());
            }
            eventService.createApiEvent(
                executionContext,
                singleton(executionContext.getEnvironmentId()),
                EventType.UNPUBLISH_API,
                null,
                properties
            );

            // Delete pages
            pageService.deleteAllByApi(executionContext, apiId);

            // Delete top API
            topApiService.delete(executionContext, apiId);
            // Delete API
            apiRepository.delete(apiId);
            // Delete memberships
            membershipService.deleteReference(executionContext, MembershipReferenceType.API, apiId);
            // Delete notifications
            genericNotificationConfigService.deleteReference(NotificationReferenceType.API, apiId);
            portalNotificationConfigService.deleteReference(NotificationReferenceType.API, apiId);
            // Delete alerts
            final List<AlertTriggerEntity> alerts = alertService.findByReferenceWithEventCounts(AlertReferenceType.API, apiId);
            alerts.forEach(alert -> alertService.delete(alert.getId(), alert.getReferenceId()));
            // delete all reference on api quality rule
            apiQualityRuleRepository.deleteByApi(apiId);
            // Audit
            auditService.createApiAuditLog(executionContext, apiId, Collections.emptyMap(), API_DELETED, new Date(), api, null);
            // remove from search engine
            searchEngineService.delete(executionContext, convert(executionContext, api));

            mediaService.deleteAllByApi(apiId);

            apiMetadataService.deleteAllByApi(executionContext, apiId);
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to delete API {}", apiId, ex);
            throw new TechnicalManagementException("An error occurs while trying to delete API " + apiId, ex);
        }
    }

    @Override
    public ApiEntity start(ExecutionContext executionContext, String apiId, String userId) {
        try {
            LOGGER.debug("Start API {}", apiId);
            ApiEntity apiEntity = updateLifecycle(executionContext, apiId, LifecycleState.STARTED, userId);
            notifierService.trigger(
                executionContext,
                ApiHook.API_STARTED,
                apiId,
                new NotificationParamsBuilder().api(apiEntity).user(userService.findById(executionContext, userId)).build()
            );
            return apiEntity;
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to start API {}", apiId, ex);
            throw new TechnicalManagementException("An error occurs while trying to start API " + apiId, ex);
        }
    }

    @Override
    public ApiEntity stop(ExecutionContext executionContext, String apiId, String userId) {
        try {
            LOGGER.debug("Stop API {}", apiId);
            ApiEntity apiEntity = updateLifecycle(executionContext, apiId, LifecycleState.STOPPED, userId);
            notifierService.trigger(
                executionContext,
                ApiHook.API_STOPPED,
                apiId,
                new NotificationParamsBuilder().api(apiEntity).user(userService.findById(executionContext, userId)).build()
            );
            return apiEntity;
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to stop API {}", apiId, ex);
            throw new TechnicalManagementException("An error occurs while trying to stop API " + apiId, ex);
        }
    }

    @Override
    public boolean isSynchronized(ExecutionContext executionContext, String apiId) {
        try {
            // 1_ First, check the API state
            ApiEntity api = findById(executionContext, apiId);

            // The state of the api is managed by kubernetes. There is no synchronization allowed from management.
            if (DefinitionContext.isKubernetes(api.getDefinitionContext())) {
                return true;
            }

            Map<String, Object> properties = new HashMap<>();
            properties.put(Event.EventProperties.API_ID.getValue(), apiId);

            io.gravitee.common.data.domain.Page<EventEntity> events = eventService.search(
                executionContext,
                Arrays.asList(PUBLISH_API, EventType.UNPUBLISH_API),
                properties,
                0,
                0,
                0,
                1,
                singletonList(executionContext.getEnvironmentId())
            );

            if (!events.getContent().isEmpty()) {
                // According to page size, we know that we have only one element in the list
                EventEntity lastEvent = events.getContent().get(0);
                boolean sync = false;
                if (PUBLISH_API.equals(lastEvent.getType())) {
                    //TODO: Done only for backward compatibility with 0.x. Must be removed later (1.1.x ?)
                    boolean enabled = objectMapper.getDeserializationConfig().isEnabled(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
                    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                    Api payloadEntity = objectMapper.readValue(lastEvent.getPayload(), Api.class);
                    objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, enabled);

                    final ApiEntity deployedApi = convert(executionContext, payloadEntity, false);
                    // Remove policy description from sync check
                    removeDescriptionFromPolicies(api);
                    removeDescriptionFromPolicies(deployedApi);

                    sync = synchronizationService.checkSynchronization(ApiEntity.class, deployedApi, api);

                    // 2_ If API definition is synchronized, check if there is any modification for API's plans
                    // but only for published or closed plan
                    if (sync) {
                        Set<PlanEntity> plans = planService.findByApi(executionContext, api.getId());
                        sync =
                            plans
                                .stream()
                                .noneMatch(
                                    plan -> plan.getStatus() != PlanStatus.STAGING && plan.getNeedRedeployAt().after(api.getDeployedAt())
                                );
                    }
                }
                return sync;
            }
        } catch (Exception e) {
            LOGGER.error("An error occurs while trying to check API synchronization state {}", apiId, e);
        }

        return false;
    }

    private void removeDescriptionFromPolicies(final ApiEntity api) {
        if (api.getPaths() != null) {
            api
                .getPaths()
                .forEach(
                    (s, rules) -> {
                        if (rules != null) {
                            rules.forEach(rule -> rule.setDescription(""));
                        }
                    }
                );
        }
    }

    @Override
    public ApiEntity deploy(
        ExecutionContext executionContext,
        String apiId,
        String userId,
        EventType eventType,
        ApiDeploymentEntity apiDeploymentEntity
    ) {
        try {
            LOGGER.debug("Deploy API : {}", apiId);

            return deployCurrentAPI(executionContext, apiId, userId, eventType, apiDeploymentEntity);
        } catch (Exception ex) {
            LOGGER.error("An error occurs while trying to deploy API: {}", apiId, ex);
            throw new TechnicalManagementException("An error occurs while trying to deploy API: " + apiId, ex);
        }
    }

    @Override
    public ApiEntity rollback(ExecutionContext executionContext, String apiId, RollbackApiEntity rollbackApiEntity) {
        LOGGER.debug("Rollback API : {}", apiId);

        try {
            // Audit
            auditService.createApiAuditLog(executionContext, apiId, Collections.emptyMap(), API_ROLLBACKED, new Date(), null, null);

            return apiDuplicatorService.updateWithImportedDefinition(
                executionContext,
                apiId,
                objectMapper.writeValueAsString(rollbackApiEntity)
            );
        } catch (Exception ex) {
            LOGGER.error("An error occurs while trying to rollback API: {}", apiId, ex);
            throw new TechnicalManagementException("An error occurs while trying to rollback API: " + apiId, ex);
        }
    }

    private ApiEntity deployCurrentAPI(
        ExecutionContext executionContext,
        String apiId,
        String userId,
        EventType eventType,
        ApiDeploymentEntity apiDeploymentEntity
    ) throws Exception {
        Api api = apiRepository.findById(apiId).orElseThrow(() -> new ApiNotFoundException(apiId));

        if (DefinitionContext.isKubernetes(api.getOrigin())) {
            throw new ApiNotManagedException("The api is managed externally (" + api.getOrigin() + "). Unable to deploy it.");
        }

        // add deployment date
        api.setUpdatedAt(new Date());
        api.setDeployedAt(api.getUpdatedAt());
        api = apiRepository.update(api);

        Map<String, String> properties = new HashMap<>();
        properties.put(Event.EventProperties.API_ID.getValue(), api.getId());
        properties.put(Event.EventProperties.USER.getValue(), userId);

        // Clear useless field for history
        api.setPicture(null);

        addDeploymentLabelToProperties(executionContext, apiId, eventType, properties, apiDeploymentEntity);

        // And create event
        eventService.createApiEvent(executionContext, singleton(executionContext.getEnvironmentId()), eventType, api, properties);

        final ApiEntity deployed = convert(executionContext, singletonList(api)).iterator().next();

        if (getAuthenticatedUser() != null && !getAuthenticatedUser().isSystem()) {
            apiNotificationService.triggerDeployNotification(executionContext, deployed);
        }

        return deployed;
    }

    private void addDeploymentLabelToProperties(
        ExecutionContext executionContext,
        String apiId,
        EventType eventType,
        Map<String, String> properties,
        ApiDeploymentEntity apiDeploymentEntity
    ) {
        if (PUBLISH_API.equals(eventType)) {
            final EventQuery query = new EventQuery();
            query.setApi(apiId);
            query.setTypes(singleton(PUBLISH_API));

            final Optional<EventEntity> optEvent = eventService
                .search(executionContext, query)
                .stream()
                .max(comparing(EventEntity::getCreatedAt));

            String lastDeployNumber = optEvent.isPresent()
                ? optEvent.get().getProperties().getOrDefault(Event.EventProperties.DEPLOYMENT_NUMBER.getValue(), "0")
                : "0";
            String newDeployNumber = Long.toString(Long.parseLong(lastDeployNumber) + 1);
            properties.put(Event.EventProperties.DEPLOYMENT_NUMBER.getValue(), newDeployNumber);

            if (apiDeploymentEntity != null && StringUtils.isNotEmpty(apiDeploymentEntity.getDeploymentLabel())) {
                properties.put(Event.EventProperties.DEPLOYMENT_LABEL.getValue(), apiDeploymentEntity.getDeploymentLabel());
            }
        }
    }

    /**
     * Allows to deploy the last published API
     * @param apiId the API id
     * @param userId the user id
     * @param eventType the event type
     * @return The persisted API or null
     * @throws TechnicalException if an exception occurs while saving the API
     */
    private ApiEntity deployLastPublishedAPI(ExecutionContext executionContext, String apiId, String userId, EventType eventType)
        throws TechnicalException {
        final EventQuery query = new EventQuery();
        query.setApi(apiId);
        query.setTypes(singleton(PUBLISH_API));

        final Optional<EventEntity> optEvent = eventService
            .search(executionContext, query)
            .stream()
            .max(comparing(EventEntity::getCreatedAt));

        try {
            if (optEvent.isPresent()) {
                EventEntity event = optEvent.get();
                JsonNode node = objectMapper.readTree(event.getPayload());
                Api lastPublishedAPI = objectMapper.convertValue(node, Api.class);
                lastPublishedAPI.setLifecycleState(convert(eventType));
                lastPublishedAPI.setUpdatedAt(new Date());
                lastPublishedAPI.setDeployedAt(new Date());
                Map<String, String> properties = new HashMap<>();
                properties.put(Event.EventProperties.API_ID.getValue(), lastPublishedAPI.getId());
                properties.put(Event.EventProperties.USER.getValue(), userId);

                // Clear useless field for history
                lastPublishedAPI.setPicture(null);

                // And create event
                eventService.createApiEvent(
                    executionContext,
                    singleton(executionContext.getEnvironmentId()),
                    eventType,
                    lastPublishedAPI,
                    properties
                );
                return null;
            } else {
                // this is the first time we start the api without previously deployed id.
                // let's do it.
                return this.deploy(executionContext, apiId, userId, PUBLISH_API, new ApiDeploymentEntity());
            }
        } catch (Exception e) {
            LOGGER.error("An error occurs while trying to deploy last published API {}", apiId, e);
            throw new TechnicalException("An error occurs while trying to deploy last published API " + apiId, e);
        }
    }

    @Override
    public String exportAsJson(ExecutionContext executionContext, final String apiId, String exportVersion, String... filteredFields) {
        ApiEntity apiEntity = findById(executionContext, apiId);
        // set metadata for serialize process
        Map<String, Object> metadata = new HashMap<>();
        metadata.put(ApiSerializer.METADATA_EXPORT_VERSION, exportVersion);
        metadata.put(ApiSerializer.METADATA_FILTERED_FIELDS_LIST, Arrays.asList(filteredFields));
        apiEntity.setMetadata(metadata);

        try {
            return objectMapper.writeValueAsString(apiEntity);
        } catch (final Exception e) {
            LOGGER.error("An error occurs while trying to JSON serialize the API {}", apiEntity, e);
        }
        return "";
    }

    @Override
    public InlinePictureEntity getPicture(ExecutionContext executionContext, String apiId) {
        Api api = this.findApiById(executionContext, apiId);
        InlinePictureEntity imageEntity = new InlinePictureEntity();
        if (api.getPicture() != null) {
            String[] parts = api.getPicture().split(";", 2);
            imageEntity.setType(parts[0].split(":")[1]);
            String base64Content = api.getPicture().split(",", 2)[1];
            imageEntity.setContent(DatatypeConverter.parseBase64Binary(base64Content));
        } else {
            getDefaultPicture()
                .ifPresent(
                    content -> {
                        imageEntity.setType("image/png");
                        imageEntity.setContent(content);
                    }
                );
        }

        return imageEntity;
    }

    private Optional<byte[]> getDefaultPicture() {
        Optional<byte[]> content = Optional.empty();
        if (!Strings.isNullOrEmpty(defaultApiIcon)) {
            try {
                content = of(IOUtils.toByteArray(new FileInputStream(defaultApiIcon)));
            } catch (IOException ioe) {
                LOGGER.error("Default icon for API does not exist", ioe);
            }
        }
        return content;
    }

    @Override
    public InlinePictureEntity getBackground(ExecutionContext executionContext, String apiId) {
        Api api = this.findApiById(executionContext, apiId);
        InlinePictureEntity imageEntity = new InlinePictureEntity();
        if (api.getBackground() != null) {
            String[] parts = api.getBackground().split(";", 2);
            imageEntity.setType(parts[0].split(":")[1]);
            String base64Content = api.getBackground().split(",", 2)[1];
            imageEntity.setContent(DatatypeConverter.parseBase64Binary(base64Content));
        }

        return imageEntity;
    }

    @Override
    public ApiEntity migrate(ExecutionContext executionContext, String apiId) {
        final ApiEntity apiEntity = findById(executionContext, apiId);
        final Set<PolicyEntity> policies = policyService.findAll();
        Set<PlanEntity> plans = planService.findByApi(executionContext, apiId);

        ApiEntity migratedApi = apiv1toAPIV2Converter.migrateToV2(apiEntity, policies, plans);

        return this.update(executionContext, apiId, apiConverter.toUpdateApiEntity(migratedApi));
    }

    @Override
    public ApiEntity importPathMappingsFromPage(
        ExecutionContext executionContext,
        final ApiEntity apiEntity,
        final String page,
        DefinitionVersion definitionVersion
    ) {
        final PageEntity pageEntity = pageService.findById(page);
        if (SWAGGER.name().equals(pageEntity.getType())) {
            final ImportSwaggerDescriptorEntity importSwaggerDescriptorEntity = new ImportSwaggerDescriptorEntity();
            importSwaggerDescriptorEntity.setPayload(pageEntity.getContent());
            importSwaggerDescriptorEntity.setWithPathMapping(true);
            final SwaggerApiEntity swaggerApiEntity = swaggerService.createAPI(
                executionContext,
                importSwaggerDescriptorEntity,
                definitionVersion
            );
            apiEntity.getPathMappings().addAll(swaggerApiEntity.getPathMappings());
        }

        return update(executionContext, apiEntity.getId(), apiConverter.toUpdateApiEntity(apiEntity));
    }

    @Override
    public Page<ApiEntity> search(ExecutionContext executionContext, final ApiQuery query, Sortable sortable, Pageable pageable) {
        try {
            LOGGER.debug("Search paginated APIs by {}", query);

            Optional<Collection<String>> optionalTargetIds = this.searchInDefinition(executionContext, query);

            if (optionalTargetIds.isPresent()) {
                Collection<String> targetIds = optionalTargetIds.get();
                if (targetIds.isEmpty()) {
                    return new Page(Collections.emptyList(), 0, 0, 0);
                }
                query.setIds(targetIds);
            }

            return convert(
                executionContext,
                apiRepository.search(
                    queryToCriteria(executionContext, query).build(),
                    convert(sortable),
                    convert(pageable),
                    new ApiFieldExclusionFilter.Builder().excludePicture().build()
                )
            );
        } catch (TechnicalException ex) {
            final String errorMessage = "An error occurs while trying to search for paginated APIs: " + query;
            LOGGER.error(errorMessage, ex);
            throw new TechnicalManagementException(errorMessage, ex);
        }
    }

    private Page<ApiEntity> convert(ExecutionContext executionContext, Page<Api> page) throws TechnicalException {
        return new Page<>(
            this.convert(executionContext, page.getContent()),
            page.getPageNumber(),
            (int) page.getPageElements(),
            page.getTotalElements()
        );
    }

    @Override
    public Collection<ApiEntity> search(ExecutionContext executionContext, final ApiQuery query) {
        LOGGER.debug("Search APIs by {}", query);

        Optional<Collection<String>> optionalTargetIds = this.searchInDefinition(executionContext, query);

        if (optionalTargetIds.isPresent()) {
            Collection<String> targetIds = optionalTargetIds.get();
            if (targetIds.isEmpty()) {
                return Collections.emptySet();
            }
            query.setIds(targetIds);
        }

        List<Api> apis = apiRepository.search(queryToCriteria(executionContext, query).build());
        return this.convert(executionContext, apis);
    }

    @Override
    public Collection<String> searchIds(ExecutionContext executionContext, ApiQuery query) {
        try {
            LOGGER.debug("Search API ids by {}", query);
            Optional<Collection<String>> optionalTargetIds = this.searchInDefinition(executionContext, query);

            if (optionalTargetIds.isPresent()) {
                Collection<String> targetIds = optionalTargetIds.get();
                if (targetIds.isEmpty()) {
                    return Collections.emptySet();
                }
                query.setIds(targetIds);
            }

            return apiRepository.searchIds(queryToCriteria(executionContext, query).build());
        } catch (Exception ex) {
            final String errorMessage = "An error occurs while trying to search for API ids: " + query;
            LOGGER.error(errorMessage, ex);
            throw new TechnicalManagementException(errorMessage, ex);
        }
    }

    @Override
    public Page<ApiEntity> search(
        ExecutionContext executionContext,
        String query,
        Map<String, Object> filters,
        Sortable sortable,
        Pageable pageable
    ) {
        try {
            LOGGER.debug("Search paged APIs by {}", query);

            Collection<String> apiIds = this.searchIds(executionContext, query, filters, sortable);

            if (apiIds.isEmpty()) {
                return new Page<>(emptyList(), 0, 0, 0);
            }

            return loadPage(executionContext, apiIds, pageable);
        } catch (TechnicalException ex) {
            LOGGER.error("An error occurs while trying to search paged apis", ex);
            throw new TechnicalManagementException("An error occurs while trying to search paged apis", ex);
        }
    }

    @Override
    public Collection<ApiEntity> search(ExecutionContext executionContext, String query, Map<String, Object> filters) {
        return this.searchInDefinition(executionContext, query, filters)
            .getDocuments()
            .stream()
            .map(apiId -> findById(executionContext, apiId))
            .collect(toList());
    }

    /**
     * This method use ApiQuery to search in indexer for fields in api definition
     *
     * @param executionContext
     * @param apiQuery
     * @return Optional<List < String>> an optional list of api ids and Optional.empty()
     * if ApiQuery doesn't contain fields stores in the api definition.
     */
    private Optional<Collection<String>> searchInDefinition(ExecutionContext executionContext, ApiQuery apiQuery) {
        if (apiQuery == null) {
            return Optional.empty();
        }
        Query<ApiEntity> searchEngineQuery = convert(apiQuery).build();
        if (isBlank(searchEngineQuery.getQuery())) {
            return Optional.empty();
        }

        SearchResult matchApis = searchEngineService.search(executionContext, addDefaultExcludedFilters(searchEngineQuery));
        return Optional.of(matchApis.getDocuments());
    }

    private SearchResult searchInDefinition(ExecutionContext executionContext, String query, Map<String, Object> filters) {
        return this.searchInDefinition(executionContext, query, filters, null);
    }

    private SearchResult searchInDefinition(
        ExecutionContext executionContext,
        String query,
        Map<String, Object> filters,
        Sortable sortable
    ) {
        Query<ApiEntity> searchEngineQuery = addDefaultExcludedFilters(
            QueryBuilder.create(ApiEntity.class).setQuery(query).setSort(sortable).setFilters(filters).build()
        );
        return searchEngineService.search(executionContext, searchEngineQuery);
    }

    private QueryBuilder<ApiEntity> convert(ApiQuery query) {
        QueryBuilder<ApiEntity> searchEngineQuery = QueryBuilder.create(ApiEntity.class);
        if (query.getIds() != null && !query.getIds().isEmpty()) {
            Map<String, Object> filters = new HashMap<>();
            filters.put("api", query.getIds());
            searchEngineQuery.setFilters(filters);
        }

        if (!isBlank(query.getContextPath())) {
            searchEngineQuery.addExplicitFilter("paths", query.getContextPath());
        }
        if (!isBlank(query.getTag())) {
            searchEngineQuery.addExplicitFilter("tag", query.getTag());
        }
        return searchEngineQuery;
    }

    @Override
    public Collection<String> searchIds(ExecutionContext executionContext, String query, Map<String, Object> filters, Sortable sortable) {
        return this.searchInDefinition(executionContext, query, filters, sortable).getDocuments();
    }

    @Override
    public List<ApiHeaderEntity> getPortalHeaders(ExecutionContext executionContext, String apiId) {
        List<ApiHeaderEntity> entities = apiHeaderService.findAll(executionContext.getEnvironmentId());
        GenericApiModel genericApiModel = apiTemplateService.findByIdForTemplates(executionContext, apiId);
        Map<String, Object> model = new HashMap<>();
        model.put("api", genericApiModel);
        entities.forEach(
            entity -> {
                if (entity.getValue().contains("${")) {
                    String entityValue =
                        this.notificationTemplateService.resolveInlineTemplateWithParam(
                                executionContext.getOrganizationId(),
                                entity.getId() + entity.getUpdatedAt().toString(),
                                entity.getValue(),
                                model
                            );
                    entity.setValue(entityValue);
                }
            }
        );
        return entities
            .stream()
            .filter(apiHeaderEntity -> apiHeaderEntity.getValue() != null && !apiHeaderEntity.getValue().isEmpty())
            .collect(Collectors.toList());
    }

    @Override
    public ApiEntity askForReview(
        ExecutionContext executionContext,
        final String apiId,
        final String userId,
        final ReviewEntity reviewEntity
    ) {
        LOGGER.debug("Ask for review API {}", apiId);
        return updateWorkflowReview(
            executionContext,
            apiId,
            userId,
            ApiHook.ASK_FOR_REVIEW,
            WorkflowState.IN_REVIEW,
            reviewEntity.getMessage()
        );
    }

    @Override
    public ApiEntity acceptReview(
        ExecutionContext executionContext,
        final String apiId,
        final String userId,
        final ReviewEntity reviewEntity
    ) {
        LOGGER.debug("Accept review API {}", apiId);
        return updateWorkflowReview(executionContext, apiId, userId, ApiHook.REVIEW_OK, WorkflowState.REVIEW_OK, reviewEntity.getMessage());
    }

    @Override
    public ApiEntity rejectReview(
        ExecutionContext executionContext,
        final String apiId,
        final String userId,
        final ReviewEntity reviewEntity
    ) {
        LOGGER.debug("Reject review API {}", apiId);
        return updateWorkflowReview(
            executionContext,
            apiId,
            userId,
            ApiHook.REQUEST_FOR_CHANGES,
            WorkflowState.REQUEST_FOR_CHANGES,
            reviewEntity.getMessage()
        );
    }

    @Override
    public boolean hasHealthCheckEnabled(ApiEntity api, boolean mustBeEnabledOnAllEndpoints) {
        boolean globalHC =
            api.getServices() != null &&
            api.getServices().getAll() != null &&
            api.getServices().getAll().stream().anyMatch(service -> service.isEnabled() && service instanceof HealthCheckService);
        if (globalHC) {
            return true;
        } else {
            final Predicate<Endpoint> endpointHealthCheckEnabledPredicate = endpoint -> {
                if (isHttpEndpoint(endpoint)) {
                    return endpoint.getHealthCheck() != null && endpoint.getHealthCheck().isEnabled();
                } else {
                    return false;
                }
            };
            if (mustBeEnabledOnAllEndpoints) {
                return api
                    .getProxy()
                    .getGroups()
                    .stream()
                    .allMatch(group -> group.getEndpoints().stream().allMatch(endpointHealthCheckEnabledPredicate));
            } else {
                return (
                    api.getProxy() != null &&
                    api.getProxy().getGroups() != null &&
                    api
                        .getProxy()
                        .getGroups()
                        .stream()
                        .anyMatch(
                            group ->
                                group.getEndpoints() != null && group.getEndpoints().stream().anyMatch(endpointHealthCheckEnabledPredicate)
                        )
                );
            }
        }
    }

    private ApiEntity updateWorkflowReview(
        ExecutionContext executionContext,
        final String apiId,
        final String userId,
        final ApiHook hook,
        final WorkflowState workflowState,
        final String workflowMessage
    ) {
        Workflow workflow = workflowService.create(WorkflowReferenceType.API, apiId, REVIEW, userId, workflowState, workflowMessage);
        final ApiEntity apiEntity = findById(executionContext, apiId);
        apiEntity.setWorkflowState(workflowState);

        final UserEntity user = userService.findById(executionContext, userId);
        notifierService.trigger(executionContext, hook, apiId, new NotificationParamsBuilder().api(apiEntity).user(user).build());

        // Find all reviewers of the API and send them a notification email
        if (hook.equals(ApiHook.ASK_FOR_REVIEW)) {
            List<String> reviewersEmail = findAllReviewersEmail(executionContext, apiId);
            this.emailService.sendAsyncEmailNotification(
                    executionContext,
                    new EmailNotificationBuilder()
                        .params(new NotificationParamsBuilder().api(apiEntity).user(user).build())
                        .to(reviewersEmail.toArray(new String[reviewersEmail.size()]))
                        .template(EmailNotificationBuilder.EmailTemplate.API_ASK_FOR_REVIEW)
                        .build()
                );
        }

        Map<Audit.AuditProperties, String> properties = new HashMap<>();
        properties.put(Audit.AuditProperties.USER, userId);
        properties.put(Audit.AuditProperties.API, apiId);

        Workflow.AuditEvent evtType = null;
        switch (workflowState) {
            case REQUEST_FOR_CHANGES:
                evtType = API_REVIEW_REJECTED;
                break;
            case REVIEW_OK:
                evtType = API_REVIEW_ACCEPTED;
                break;
            default:
                evtType = API_REVIEW_ASKED;
                break;
        }

        auditService.createApiAuditLog(executionContext, apiId, properties, evtType, new Date(), null, workflow);
        return apiEntity;
    }

    private List<String> findAllReviewersEmail(ExecutionContext executionContext, String apiId) {
        final RolePermissionAction[] acls = { RolePermissionAction.UPDATE };

        // find direct members of the API
        Set<String> reviewerEmails = roleService
            .findByScope(RoleScope.API, executionContext.getOrganizationId())
            .stream()
            .filter(role -> this.roleService.hasPermission(role.getPermissions(), ApiPermission.REVIEWS, acls))
            .flatMap(
                role -> this.membershipService.getMembershipsByReferenceAndRole(MembershipReferenceType.API, apiId, role.getId()).stream()
            )
            .filter(m -> m.getMemberType().equals(MembershipMemberType.USER))
            .map(MembershipEntity::getMemberId)
            .distinct()
            .map(id -> this.userService.findById(executionContext, id))
            .map(UserEntity::getEmail)
            .filter(Objects::nonNull)
            .collect(toSet());

        // find reviewers in group attached to the API
        final Set<String> groups = this.findById(executionContext, apiId).getGroups();
        if (groups != null && !groups.isEmpty()) {
            groups.forEach(
                group -> {
                    reviewerEmails.addAll(
                        roleService
                            .findByScope(RoleScope.API, executionContext.getOrganizationId())
                            .stream()
                            .filter(role -> this.roleService.hasPermission(role.getPermissions(), ApiPermission.REVIEWS, acls))
                            .flatMap(
                                role ->
                                    this.membershipService.getMembershipsByReferenceAndRole(
                                            MembershipReferenceType.GROUP,
                                            group,
                                            role.getId()
                                        )
                                        .stream()
                            )
                            .filter(m -> m.getMemberType().equals(MembershipMemberType.USER))
                            .map(MembershipEntity::getMemberId)
                            .distinct()
                            .map(id -> this.userService.findById(executionContext, id))
                            .map(UserEntity::getEmail)
                            .filter(Objects::nonNull)
                            .collect(toSet())
                    );
                }
            );
        }

        return new ArrayList<>(reviewerEmails);
    }

    private ApiCriteria.Builder queryToCriteria(ExecutionContext executionContext, ApiQuery query) {
        final ApiCriteria.Builder builder = getDefaultApiCriteriaBuilder().environmentId(executionContext.getEnvironmentId());
        if (query == null) {
            return builder;
        }
        builder.label(query.getLabel()).name(query.getName()).version(query.getVersion());

        if (!isBlank(query.getCategory())) {
            builder.category(categoryService.findById(query.getCategory(), executionContext.getEnvironmentId()).getId());
        }
        if (query.getGroups() != null && !query.getGroups().isEmpty()) {
            builder.groups(query.getGroups());
        }
        if (!isBlank(query.getState())) {
            builder.state(LifecycleState.valueOf(query.getState()));
        }
        if (query.getVisibility() != null) {
            builder.visibility(Visibility.valueOf(query.getVisibility().name()));
        }
        if (query.getLifecycleStates() != null) {
            builder.lifecycleStates(
                query
                    .getLifecycleStates()
                    .stream()
                    .map(apiLifecycleState -> ApiLifecycleState.valueOf(apiLifecycleState.name()))
                    .collect(toList())
            );
        }
        if (query.getIds() != null && !query.getIds().isEmpty()) {
            builder.ids(query.getIds());
        }
        if (query.getCrossId() != null && !query.getCrossId().isEmpty()) {
            builder.crossId(query.getCrossId());
        }

        return builder;
    }

    private ApiEntity updateLifecycle(ExecutionContext executionContext, String apiId, LifecycleState lifecycleState, String username)
        throws TechnicalException {
        Optional<Api> optApi = apiRepository.findById(apiId);
        if (optApi.isPresent()) {
            Api api = optApi.get();

            Api previousApi = new Api(api);
            api.setUpdatedAt(new Date());
            api.setLifecycleState(lifecycleState);
            ApiEntity apiEntity = convert(executionContext, apiRepository.update(api), getPrimaryOwner(executionContext, api), null);
            // Audit
            auditService.createApiAuditLog(
                executionContext,
                apiId,
                Collections.emptyMap(),
                API_UPDATED,
                api.getUpdatedAt(),
                previousApi,
                api
            );

            EventType eventType = null;
            switch (lifecycleState) {
                case STARTED:
                    eventType = EventType.START_API;
                    break;
                case STOPPED:
                    eventType = EventType.STOP_API;
                    break;
                default:
                    break;
            }

            if (!DefinitionContext.isKubernetes(api.getOrigin())) {
                final ApiEntity deployedApi = deployLastPublishedAPI(executionContext, apiId, username, eventType);
                if (deployedApi != null) {
                    return deployedApi;
                }
            }
            return apiEntity;
        } else {
            throw new ApiNotFoundException(apiId);
        }
    }

    private void auditApiLogging(ExecutionContext executionContext, Api apiToUpdate, Api apiUpdated) {
        try {
            // get old logging configuration
            io.gravitee.definition.model.Api apiToUpdateDefinition = objectMapper.readValue(
                apiToUpdate.getDefinition(),
                io.gravitee.definition.model.Api.class
            );
            Logging loggingToUpdate = apiToUpdateDefinition.getProxy().getLogging();

            // get new logging configuration
            io.gravitee.definition.model.Api apiUpdatedDefinition = objectMapper.readValue(
                apiUpdated.getDefinition(),
                io.gravitee.definition.model.Api.class
            );
            Logging loggingUpdated = apiUpdatedDefinition.getProxy().getLogging();

            // no changes for logging configuration, continue
            if (
                loggingToUpdate == loggingUpdated ||
                (
                    loggingToUpdate != null &&
                    loggingUpdated != null &&
                    Objects.equals(loggingToUpdate.getMode(), loggingUpdated.getMode()) &&
                    Objects.equals(loggingToUpdate.getCondition(), loggingUpdated.getCondition())
                )
            ) {
                return;
            }

            // determine the audit event type
            Api.AuditEvent auditEvent;
            if (
                (loggingToUpdate == null || loggingToUpdate.getMode().equals(LoggingMode.NONE)) &&
                (loggingUpdated != null && !loggingUpdated.getMode().equals(LoggingMode.NONE))
            ) {
                auditEvent = Api.AuditEvent.API_LOGGING_ENABLED;
            } else if (
                (loggingToUpdate != null && !loggingToUpdate.getMode().equals(LoggingMode.NONE)) &&
                (loggingUpdated == null || loggingUpdated.getMode().equals(LoggingMode.NONE))
            ) {
                auditEvent = Api.AuditEvent.API_LOGGING_DISABLED;
            } else {
                auditEvent = Api.AuditEvent.API_LOGGING_UPDATED;
            }

            // Audit
            auditService.createApiAuditLog(
                executionContext,
                apiUpdated.getId(),
                Collections.emptyMap(),
                auditEvent,
                new Date(),
                loggingToUpdate,
                loggingUpdated
            );
        } catch (Exception ex) {
            LOGGER.error("An error occurs while auditing API logging configuration for API: {}", apiUpdated.getId(), ex);
            throw new TechnicalManagementException(
                "An error occurs while auditing API logging configuration for API: " + apiUpdated.getId(),
                ex
            );
        }
    }

    private List<ApiEntity> convert(ExecutionContext executionContext, final List<Api> apis) {
        if (apis == null || apis.isEmpty()) {
            return Collections.emptyList();
        }
        final List<String> apiIds = apis.stream().map(Api::getId).collect(toList());
        Map<String, PrimaryOwnerEntity> primaryOwners = primaryOwnerService.getPrimaryOwners(executionContext, apiIds);
        Set<String> apiWithoutPo = apiIds.stream().filter(apiId -> !primaryOwners.containsKey(apiId)).collect(toSet());
        Stream<Api> streamApis = apis.stream();
        if (!apiWithoutPo.isEmpty()) {
            String apisAsString = String.join(" / ", apiWithoutPo);
            LOGGER.error("{} apis has no identified primary owners in this list {}.", apiWithoutPo.size(), apisAsString);
            streamApis = streamApis.filter(api -> !apiIds.contains(api.getId()));
        }
        final List<CategoryEntity> categories = categoryService.findAll(executionContext.getEnvironmentId());

        return streamApis
            .map(publicApi -> this.convert(executionContext, publicApi, primaryOwners.get(publicApi.getId()), categories))
            .collect(toList());
    }

    private ApiEntity convert(ExecutionContext executionContext, Api api) {
        return convert(executionContext, api, true);
    }

    private ApiEntity convert(ExecutionContext executionContext, Api api, boolean readDatabaseFlows) {
        return apiConverter.toApiEntity(executionContext, api, null, null, readDatabaseFlows);
    }

    private ApiEntity convert(
        ExecutionContext executionContext,
        Api api,
        PrimaryOwnerEntity primaryOwner,
        List<CategoryEntity> categories
    ) {
        return apiConverter.toApiEntity(executionContext, api, primaryOwner, categories, true);
    }

    private Api convert(ExecutionContext executionContext, String apiId, UpdateApiEntity updateApiEntity, String apiDefinition) {
        Api api = new Api();
        api.setId(apiId.trim());
        api.setCrossId(updateApiEntity.getCrossId());
        if (updateApiEntity.getVisibility() != null) {
            api.setVisibility(Visibility.valueOf(updateApiEntity.getVisibility().toString()));
        }

        api.setVersion(updateApiEntity.getVersion().trim());
        api.setName(updateApiEntity.getName().trim());
        api.setDescription(updateApiEntity.getDescription().trim());
        api.setPicture(updateApiEntity.getPicture());
        api.setBackground(updateApiEntity.getBackground());

        api.setDefinition(buildApiDefinition(apiId, apiDefinition, updateApiEntity));

        final Set<String> apiCategories = updateApiEntity.getCategories();
        if (apiCategories != null) {
            final List<CategoryEntity> categories = categoryService.findAll(executionContext.getEnvironmentId());
            final Set<String> newApiCategories = new HashSet<>(apiCategories.size());
            for (final String apiCategory : apiCategories) {
                final Optional<CategoryEntity> optionalCategory = categories
                    .stream()
                    .filter(c -> apiCategory.equals(c.getKey()) || apiCategory.equals(c.getId()))
                    .findAny();
                optionalCategory.ifPresent(category -> newApiCategories.add(category.getId()));
            }
            api.setCategories(newApiCategories);
        }

        if (updateApiEntity.getLabels() != null) {
            api.setLabels(new ArrayList<>(new HashSet<>(updateApiEntity.getLabels())));
        }

        api.setGroups(updateApiEntity.getGroups());
        api.setDisableMembershipNotifications(updateApiEntity.isDisableMembershipNotifications());

        if (updateApiEntity.getLifecycleState() != null) {
            api.setApiLifecycleState(ApiLifecycleState.valueOf(updateApiEntity.getLifecycleState().name()));
        }
        return api;
    }

    private LifecycleState convert(EventType eventType) {
        LifecycleState lifecycleState;
        switch (eventType) {
            case START_API:
                lifecycleState = LifecycleState.STARTED;
                break;
            case STOP_API:
                lifecycleState = LifecycleState.STOPPED;
                break;
            default:
                throw new IllegalArgumentException("Unknown EventType " + eventType + " to convert EventType into Lifecycle");
        }
        return lifecycleState;
    }

    private Page<ApiEntity> loadPage(ExecutionContext executionContext, Collection<String> apiIds, Pageable pageable)
        throws TechnicalException {
        pageable = buildPageable(pageable);

        int totalCount = apiIds.size();
        int startIndex = (pageable.getPageNumber() - 1) * pageable.getPageSize();

        if (pageable.getPageNumber() < 1 || (totalCount > 0 && startIndex >= totalCount)) {
            throw new PaginationInvalidException();
        }
        List<String> subsetApiIds = apiIds.stream().skip(startIndex).limit(pageable.getPageSize()).collect(toList());
        Comparator<String> orderingComparator = Comparator.comparingInt(subsetApiIds::indexOf);
        List<ApiEntity> subsetApis = subsetApiIds.isEmpty()
            ? emptyList()
            : convert(executionContext, apiRepository.search(queryToCriteria(executionContext, null).ids(subsetApiIds).build()));
        subsetApis.sort((o1, o2) -> orderingComparator.compare(o1.getId(), o2.getId()));
        return new Page<>(subsetApis, pageable.getPageNumber(), pageable.getPageSize(), apiIds.size());
    }

    /*
        Handy method to initialize a default pageable if none is provided.
     */
    private Pageable buildPageable(Pageable pageable) {
        if (pageable == null) {
            // No page specified, get all apis in one page.
            return new PageableImpl(1, Integer.MAX_VALUE);
        }

        return pageable;
    }

    protected void encryptProperties(List<PropertyEntity> properties) {
        for (PropertyEntity property : properties) {
            if (property.isEncryptable() && !property.isEncrypted()) {
                try {
                    property.setValue(dataEncryptor.encrypt(property.getValue()));
                    property.setEncrypted(true);
                } catch (GeneralSecurityException e) {
                    LOGGER.error("Error encrypting property value", e);
                }
            }
        }
    }

    @Override
    public Map<String, Long> countPublishedByUserGroupedByCategories(String userId) {
        ApiCriteria criteria = getDefaultApiCriteriaBuilder()
            .visibility(PUBLIC)
            .lifecycleStates(List.of(ApiLifecycleState.PUBLISHED))
            .build();
        ApiFieldInclusionFilter filter = ApiFieldInclusionFilter.builder().includeCategories().build();

        Set<Api> apis = apiRepository.search(criteria, filter);

        apis.addAll(findUserApis(userId, filter));

        Set<String> categories = apis.stream().map(Api::getCategories).filter(Objects::nonNull).flatMap(Set::stream).collect(toSet());

        HashMap<String, Long> groups = new HashMap<>();

        for (String category : categories) {
            groups.put(category, categoryService.getTotalApisByCategoryId(apis, category));
        }

        return groups;
    }

    private Set<Api> findUserApis(String userId, ApiFieldInclusionFilter filter) {
        if (userId == null) {
            return Set.of();
        }

        HashSet<Api> apis = new HashSet<>();

        final String[] userApiIds = membershipService
            .getMembershipsByMemberAndReference(MembershipMemberType.USER, userId, MembershipReferenceType.API)
            .stream()
            .map(MembershipEntity::getReferenceId)
            .toArray(String[]::new);

        if (userApiIds.length > 0) {
            ApiCriteria criteria = getDefaultApiCriteriaBuilder()
                .lifecycleStates(List.of(ApiLifecycleState.PUBLISHED))
                .ids(userApiIds)
                .build();
            Set<Api> userApis = apiRepository.search(criteria, filter);
            apis.addAll(userApis);
        }

        final String[] groupIds = membershipService
            .getMembershipsByMemberAndReference(MembershipMemberType.USER, userId, MembershipReferenceType.GROUP)
            .stream()
            .filter(
                m -> {
                    final RoleEntity roleInGroup = roleService.findById(m.getRoleId());
                    return m.getRoleId() != null && roleInGroup.getScope().equals(RoleScope.API);
                }
            )
            .map(MembershipEntity::getReferenceId)
            .toArray(String[]::new);

        if (groupIds.length > 0 && groupIds[0] != null) {
            ApiCriteria criteria = getDefaultApiCriteriaBuilder()
                .lifecycleStates(List.of(ApiLifecycleState.PUBLISHED))
                .groups(groupIds)
                .build();
            Set<Api> groupApis = apiRepository.search(criteria, filter);
            apis.addAll(groupApis);
        }

        return apis;
    }

    @NotNull
    private ApiCriteria.Builder getDefaultApiCriteriaBuilder() {
        // By default in this service, we do not care for V4 APIs.
        List<DefinitionVersion> allowedDefinitionVersion = new ArrayList<>();
        allowedDefinitionVersion.add(null);
        allowedDefinitionVersion.add(DefinitionVersion.V1);
        allowedDefinitionVersion.add(DefinitionVersion.V2);

        return new ApiCriteria.Builder().definitionVersion(allowedDefinitionVersion);
    }

    private Query<ApiEntity> addDefaultExcludedFilters(Query<ApiEntity> searchEngineQuery) {
        // By default in this service, we do not care for V4 APIs.
        searchEngineQuery.getExcludedFilters().put(FIELD_DEFINITION_VERSION, Arrays.asList(DefinitionVersion.V4.getLabel()));
        return searchEngineQuery;
    }
}
