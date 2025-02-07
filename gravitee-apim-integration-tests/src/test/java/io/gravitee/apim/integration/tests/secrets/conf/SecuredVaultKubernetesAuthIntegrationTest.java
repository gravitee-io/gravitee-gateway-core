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
package io.gravitee.apim.integration.tests.secrets.conf;

import static io.gravitee.apim.integration.tests.secrets.SecuredVaultContainer.TESTROLE;
import static org.assertj.core.api.Assertions.assertThat;

import com.dajudge.kindcontainer.KindContainer;
import com.dajudge.kindcontainer.KindContainerVersion;
import io.github.jopenlibs.vault.VaultException;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.configuration.GatewayConfigurationBuilder;
import io.gravitee.apim.integration.tests.secrets.KubernetesHelper;
import io.gravitee.apim.integration.tests.secrets.SecuredVaultContainer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.Environment;
import org.testcontainers.containers.output.OutputFrame;

/**
 * @author Benoit BORDIGONI (benoit.bordigoni at graviteesource.com)
 * @author GraviteeSource Team
 */
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class SecuredVaultKubernetesAuthIntegrationTest extends AbstractSecuredVaultSecretProviderTest {

    private static KindDockerInternalContainer kubeContainer;

    static class KindDockerInternalContainer extends KindContainer<KindDockerInternalContainer> {

        public KindDockerInternalContainer(KindContainerVersion kindContainerVersion) {
            super(kindContainerVersion);
        }

        @Override
        public String getContainerIpAddress() {
            // Hack!!
            // This is deprecated method that internally is used by kind container as SAN for Kube CA,
            // We need to add the following so Vault can call the host where Kube runs
            return "host.docker.internal";
        }
    }

    @BeforeAll
    static void createKubeContainer() throws IOException, InterruptedException {
        kubeContainer = new KindDockerInternalContainer(KindContainerVersion.VERSION_1_29_1).withLogConsumer(console("kind  | "));
        kubeContainer.start();

        // create vault service account with roles
        // and create gravitee service account
        KubernetesHelper.apply(kubeContainer, "src/test/resources/vault/kube-auth/resources.yaml");

        // write config so the secret provider can pick it up
        Path kubeConfigFile = Files
            .createTempDirectory(KubernetesSecretProviderIntegrationTest.class.getSimpleName())
            .resolve("kube_config.yml");
        Files.writeString(kubeConfigFile, kubeContainer.getKubeconfig());
        String vaultToken = KubernetesHelper.createToken(kubeContainer, "vault");

        vaultContainer.setupKubernetesRoleAuth(kubeConfigFile, "gravitee", vaultToken);
    }

    @Nonnull
    private static Consumer<OutputFrame> console(String prefix) {
        return c -> System.out.println(prefix + c.getUtf8StringWithoutLineEnding());
    }

    @Nested
    @GatewayTest
    class DefaultNamespaceKubernetesAuth extends AbstractGatewayVaultTest {

        String password1 = UUID.randomUUID().toString();
        String password2 = UUID.randomUUID().toString();

        @Override
        protected Map<String, Object> authConfig(SecuredVaultContainer vaultContainer) throws Exception {
            String graviteeKubeAuthToken = KubernetesHelper.createToken(kubeContainer, "gravitee");
            Path kubeAuthTokenPath = Files
                .createTempDirectory(KubernetesSecretProviderIntegrationTest.class.getSimpleName())
                .resolve("token");
            Files.writeString(kubeAuthTokenPath, graviteeKubeAuthToken);

            return Map.of(
                "secrets.vault.auth.method",
                "kubernetes",
                "secrets.vault.auth.config.role",
                TESTROLE,
                "secrets.vault.auth.config.tokenPath",
                kubeAuthTokenPath.toString()
            );
        }

        @Override
        void createSecrets() throws VaultException {
            writeSecret("secret/foo", Map.of("password", password1));
            writeSecret("secret/bar", Map.of("password", password2));
        }

        @Override
        public void setupAdditionalProperties(GatewayConfigurationBuilder configurationBuilder) {
            configurationBuilder
                .setYamlProperty("foo", "secret://vault/secret/foo:password")
                .setYamlProperty("bar", "secret://vault/secret/bar:password");
        }

        @Test
        void should_be_able_to_resolve_secret() {
            Environment environment = getBean(Environment.class);
            assertThat(environment.getProperty("foo")).isEqualTo(password1);
            assertThat(environment.getProperty("bar")).isEqualTo(password2);
        }
    }
}
