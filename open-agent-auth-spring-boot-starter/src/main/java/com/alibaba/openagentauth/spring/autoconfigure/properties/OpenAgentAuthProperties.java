/*
 * Copyright 2026 Alibaba Group Holding Ltd.
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
package com.alibaba.openagentauth.spring.autoconfigure.properties;

import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.JwksConsumerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.KeyDefinitionProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.infrastructures.ServiceDefinitionProperties;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Root configuration properties for Open Agent Auth framework.
 *
 * @since 1.0
 */
@ConfigurationProperties(prefix = "open-agent-auth")
public class OpenAgentAuthProperties {

    /**
     * Whether Open Agent Auth is enabled.
     */
    private boolean enabled = true;

    /**
     * Infrastructure configuration (trust domain, keys, JWKS, service discovery).
     */
    @NestedConfigurationProperty
    private InfrastructureProperties infrastructures = new InfrastructureProperties();

    /**
     * Capabilities configuration (composable functional features).
     */
    @NestedConfigurationProperty
    private CapabilitiesProperties capabilities = new CapabilitiesProperties();

    // ========== Getters and Setters ==========

    /**
     * Gets whether Open Agent Auth is enabled.
     *
     * @return whether Open Agent Auth is enabled
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Sets whether Open Agent Auth is enabled.
     *
     * @param enabled whether Open Agent Auth is enabled
     */
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets the infrastructure configuration.
     * <p>
     * This configuration defines the shared infrastructure components used across all roles,
     * including trust domain, key management, JWKS, and service discovery.
     * </p>
     *
     * @return the infrastructure properties
     */
    public InfrastructureProperties getInfrastructures() {
        return infrastructures;
    }

    /**
     * Sets the infrastructure configuration.
     * <p>
     * This configuration controls the shared infrastructure components that are
     * used by all roles in the framework.
     * </p>
     *
     * @param infrastructures the infrastructure properties to set
     */
    public void setInfrastructures(InfrastructureProperties infrastructures) {
        this.infrastructures = infrastructures;
    }

    /**
     * Gets the capabilities configuration.
     * <p>
     * This configuration defines the functional features that can be composed by roles.
     * Each capability represents an independent feature that can be enabled or disabled.
     * </p>
     *
     * @return the capabilities properties
     */
    public CapabilitiesProperties getCapabilities() {
        return capabilities;
    }

    /**
     * Sets the capabilities configuration.
     * <p>
     * This configuration defines the functional features available for composition by roles.
     * </p>
     *
     * @param capabilities the capabilities properties to set
     */
    public void setCapabilities(CapabilitiesProperties capabilities) {
        this.capabilities = capabilities;
    }

    // ========== Convenience Accessors ==========
    // These methods reduce deep chaining (e.g., 6-layer getter chains) to a single call,
    // improving readability and adhering to the Law of Demeter.

    /**
     * Gets the trust domain string from infrastructure configuration.
     *
     * @return the trust domain URI, or the default value if not configured
     */
    public String getTrustDomain() {
        return infrastructures.getTrustDomain();
    }

    /**
     * Gets a key definition by its logical name.
     * <p>
     * This is a convenience method that replaces the deep chain:
     * {@code getInfrastructures().getKeyManagement().getKeys().get(keyName)}
     * </p>
     *
     * @param keyName the logical key name (e.g., {@code "par-jwt-signing"})
     * @return the key definition properties, or {@code null} if not found
     */
    public KeyDefinitionProperties getKeyDefinition(String keyName) {
        return infrastructures.getKeyManagement().getKeys().get(keyName);
    }

    /**
     * Gets a service definition by its logical name.
     * <p>
     * This is a convenience method that replaces the deep chain:
     * {@code getInfrastructures().getServiceDiscovery().getServices().get(serviceName)}
     * </p>
     *
     * @param serviceName the logical service name (e.g., {@code "authorization-server"})
     * @return the service definition properties, or {@code null} if not found
     */
    public ServiceDefinitionProperties getServiceDefinition(String serviceName) {
        return infrastructures.getServiceDiscovery().getServices().get(serviceName);
    }

    /**
     * Gets the base URL of a service by its logical name.
     * <p>
     * This is a convenience method that replaces the deep chain:
     * {@code getInfrastructures().getServiceDiscovery().getServices().get(serviceName).getBaseUrl()}
     * </p>
     *
     * @param serviceName the logical service name (e.g., {@code "authorization-server"})
     * @return the base URL, or {@code null} if the service is not found
     */
    public String getServiceUrl(String serviceName) {
        ServiceDefinitionProperties service = getServiceDefinition(serviceName);
        return service != null ? service.getBaseUrl() : null;
    }

    /**
     * Gets a JWKS consumer configuration by its logical name.
     * <p>
     * This is a convenience method that replaces the deep chain:
     * {@code getInfrastructures().getJwks().getConsumers().get(consumerName)}
     * </p>
     *
     * @param consumerName the logical consumer name (e.g., {@code "agent-idp"})
     * @return the JWKS consumer properties, or {@code null} if not found
     */
    public JwksConsumerProperties getJwksConsumer(String consumerName) {
        return infrastructures.getJwks().getConsumers().get(consumerName);
    }

}