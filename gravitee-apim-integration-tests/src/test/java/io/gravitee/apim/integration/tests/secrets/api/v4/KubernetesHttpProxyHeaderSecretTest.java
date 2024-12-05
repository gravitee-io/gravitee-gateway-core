package io.gravitee.apim.integration.tests.secrets.api.v4;

import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import com.graviteesource.service.secrets.SecretsService;
import io.gravitee.apim.gateway.tests.sdk.AbstractGatewayTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.configuration.GatewayConfigurationBuilder;
import io.gravitee.apim.gateway.tests.sdk.connector.EndpointBuilder;
import io.gravitee.apim.gateway.tests.sdk.connector.EntrypointBuilder;
import io.gravitee.apim.gateway.tests.sdk.secrets.SecretProviderBuilder;
import io.gravitee.apim.integration.tests.secrets.KubernetesHelper;
import io.gravitee.common.service.AbstractService;
import io.gravitee.node.secrets.plugins.SecretProviderPlugin;
import io.gravitee.plugin.endpoint.EndpointConnectorPlugin;
import io.gravitee.plugin.endpoint.http.proxy.HttpProxyEndpointConnectorFactory;
import io.gravitee.plugin.entrypoint.EntrypointConnectorPlugin;
import io.gravitee.plugin.entrypoint.http.proxy.HttpProxyEntrypointConnectorFactory;
import io.gravitee.secretprovider.kubernetes.KubernetesSecretProvider;
import io.gravitee.secretprovider.kubernetes.KubernetesSecretProviderFactory;
import io.gravitee.secretprovider.kubernetes.config.K8sConfig;
import io.gravitee.secrets.api.plugin.SecretManagerConfiguration;
import io.gravitee.secrets.api.plugin.SecretProviderFactory;
import io.vertx.core.http.HttpMethod;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientRequest;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.testcontainers.k3s.K3sContainer;

/**
 * @author Benoit BORDIGONI (benoit.bordigoni at graviteesource.com)
 * @author GraviteeSource Team
 */
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
public class KubernetesHttpProxyHeaderSecretTest {

    abstract static class AbstractKubernetesApiTest extends AbstractGatewayTest {

        Path kubeConfigFile;
        K3sContainer k3sServer;

        @AfterEach
        void cleanup() throws IOException {
            k3sServer.close();
            Files.delete(kubeConfigFile);
        }

        @Override
        public void configureGateway(GatewayConfigurationBuilder configurationBuilder) {
            try {
                kubeConfigFile =
                    Files.createTempDirectory(KubernetesHttpProxyHeaderSecretTest.class.getSimpleName()).resolve("kube_config.yml");
                configurationBuilder.setYamlProperty("api.secrets.providers[0].plugin", "kubernetes");
                configurationBuilder.setYamlProperty("api.secrets.providers[0].configuration.enabled", true);
                configurationBuilder.setYamlProperty("api.secrets.providers[0].configuration.kubeConfigFile", kubeConfigFile.toString());

                setupAdditionalProperties(configurationBuilder);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void configureEntrypoints(Map<String, EntrypointConnectorPlugin<?, ?>> entrypoints) {
            entrypoints.putIfAbsent("http-proxy", EntrypointBuilder.build("http-proxy", HttpProxyEntrypointConnectorFactory.class));
        }

        @Override
        public void configureEndpoints(Map<String, EndpointConnectorPlugin<?, ?>> endpoints) {
            endpoints.putIfAbsent("http-proxy", EndpointBuilder.build("http-proxy", HttpProxyEndpointConnectorFactory.class));
        }

        @Override
        public void configureSecretProviders(
            Set<SecretProviderPlugin<? extends SecretProviderFactory<?>, ? extends SecretManagerConfiguration>> secretProviderPlugins
        ) throws Exception {
            secretProviderPlugins.add(
                SecretProviderBuilder.build(KubernetesSecretProvider.PLUGIN_ID, KubernetesSecretProviderFactory.class, K8sConfig.class)
            );
            startK3s();
            createSecrets();
        }

        @Override
        public void configureServices(Set<Class<? extends AbstractService<?>>> services) {
            super.configureServices(services);
            services.add(SecretsService.class);
        }

        abstract void createSecrets() throws IOException, InterruptedException;

        final void startK3s() throws IOException {
            k3sServer = KubernetesHelper.getK3sServer();
            k3sServer.start();
            // write config so the secret provider can pick it up
            Files.writeString(kubeConfigFile, k3sServer.getKubeConfigYaml());
        }

        protected void setupAdditionalProperties(GatewayConfigurationBuilder configurationBuilder) {
            // no op by default
        }
    }

    @Nested
    @GatewayTest
    @DeployApi("/apis/v4/http/secrets/api-static-ref.json")
    class StaticSecretRef extends AbstractKubernetesApiTest {

        private final String apiKey = UUID.randomUUID().toString();

        @Override
        void createSecrets() throws IOException, InterruptedException {
            KubernetesHelper.createSecret(k3sServer, "default", "test", Map.of("api-key", this.apiKey));
        }

        @Test
        void should_call_api_with_k8s_api_key(HttpClient httpClient) {
            httpClient
                .rxRequest(HttpMethod.GET, "/test")
                .flatMap(HttpClientRequest::rxSend)
                .flatMap(response -> {
                    // just asserting we get a response (hence no SSL errors), no need for an API.
                    assertThat(response.statusCode()).isEqualTo(200);
                    return response.body();
                })
                .test()
                .awaitDone(10, TimeUnit.SECONDS)
                .assertComplete();

            wiremock.verify(1, getRequestedFor(urlPathEqualTo("/test")).withHeader("Authorization", equalTo("ApiKey ".concat(apiKey))));
        }
    }
}
