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

import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ClientProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.OAuth2ServerProperties;
import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.WorkloadIdentityProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Capabilities configuration properties for the Open Agent Auth framework.
 * <p>
 * This class defines capability-level configurations that can be composed by roles.
 * Each capability represents a functional feature that can be enabled/disabled independently.
 * </p>
 * <p>
 * This class is not independently bound via {@code @ConfigurationProperties}.
 * Instead, it is nested within {@link OpenAgentAuthProperties} and bound as part of
 * the {@code open-agent-auth.capabilities} prefix through the parent class.
 * </p>
 * <p>
 * <b>Capabilities Overview:</b></p>
 * <ul>
 *   <li><b>OAuth2 Server</b> - Provides OAuth 2.0 authorization server functionality</li>
 *   <li><b>OAuth2 Client</b> - Provides OAuth 2.0 client functionality for authentication</li>
 *   <li><b>Workload Identity</b> - Manages workload identities and token issuance</li>
 * </ul>
 * <p>
 * <b>Configuration Example:</b></p>
 * <pre>
 * open-agent-auth:
 *   capabilities:
 *     oauth2-server:
 *       enabled: true
 *       endpoints:
 *         authorize: /oauth2/authorize
 *         token: /oauth2/token
 *     oauth2-client:
 *       enabled: true
 *       authentication:
 *         enabled: true
 *     workload-identity:
 *       enabled: true
 * </pre>
 *
 * @since 1.0
 * @see OAuth2ServerProperties
 * @see OAuth2ClientProperties
 * @see WorkloadIdentityProperties
 */
public class CapabilitiesProperties {

    /**
     * OAuth 2.0 Server capability configuration.
     * <p>
     * Provides OAuth 2.0 authorization server functionality including authorization flows,
     * token issuance, and client management.
     * </p>
     */
    @NestedConfigurationProperty
    private OAuth2ServerProperties oauth2Server = new OAuth2ServerProperties();

    /**
     * OAuth 2.0 Client capability configuration.
     * <p>
     * Provides OAuth 2.0 client functionality for authenticating users and obtaining
     * tokens from authorization servers.
     * </p>
     */
    @NestedConfigurationProperty
    private OAuth2ClientProperties oauth2Client = new OAuth2ClientProperties();

    /**
     * Workload Identity capability configuration.
     * <p>
     * Provides workload identity management and token issuance for applications and services.
     * </p>
     */
    @NestedConfigurationProperty
    private WorkloadIdentityProperties workloadIdentity = new WorkloadIdentityProperties();

    /**
     * Gets the OAuth 2.0 Server capability configuration.
     *
     * @return the OAuth 2.0 Server capability configuration
     */
    public OAuth2ServerProperties getOAuth2Server() {
        return oauth2Server;
    }

    /**
     * Sets the OAuth 2.0 Server capability configuration.
     *
     * @param oauth2Server the OAuth 2.0 Server capability configuration to set
     */
    public void setOAuth2Server(OAuth2ServerProperties oauth2Server) {
        this.oauth2Server = oauth2Server;
    }

    /**
     * Gets the OAuth 2.0 Client capability configuration.
     *
     * @return the OAuth 2.0 Client capability configuration
     */
    public OAuth2ClientProperties getOAuth2Client() {
        return oauth2Client;
    }

    /**
     * Sets the OAuth 2.0 Client capability configuration.
     *
     * @param oauth2Client the OAuth 2.0 Client capability configuration to set
     */
    public void setOAuth2Client(OAuth2ClientProperties oauth2Client) {
        this.oauth2Client = oauth2Client;
    }

    /**
     * Gets the Workload Identity capability configuration.
     *
     * @return the Workload Identity capability configuration
     */
    public WorkloadIdentityProperties getWorkloadIdentity() {
        return workloadIdentity;
    }

    /**
     * Sets the Workload Identity capability configuration.
     *
     * @param workloadIdentity the Workload Identity capability configuration to set
     */
    public void setWorkloadIdentity(WorkloadIdentityProperties workloadIdentity) {
        this.workloadIdentity = workloadIdentity;
    }
}