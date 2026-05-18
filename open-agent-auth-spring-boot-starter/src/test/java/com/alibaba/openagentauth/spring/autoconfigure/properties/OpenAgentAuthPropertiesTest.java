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

import com.alibaba.openagentauth.spring.autoconfigure.properties.capabilities.WorkloadIdentityProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("OpenAgentAuthProperties Tests")
class OpenAgentAuthPropertiesTest {

    private OpenAgentAuthProperties properties;

    @BeforeEach
    void setUp() {
        properties = new OpenAgentAuthProperties();
    }

    @Nested
    @DisplayName("Default Values Tests")
    class DefaultValuesTests {

        @Test
        @DisplayName("Should have default enabled value as true")
        void shouldHaveDefaultEnabledAsTrue() {
            assertTrue(properties.isEnabled());
        }

        @Test
        @DisplayName("Should initialize all nested properties")
        void shouldInitializeAllNestedProperties() {
            assertNotNull(properties.getInfrastructures());
            assertNotNull(properties.getCapabilities());
        }
    }

    @Nested
    @DisplayName("Getter and Setter Tests")
    class GetterAndSetterTests {

        @Test
        @DisplayName("Should set and get enabled property")
        void shouldSetAndGetEnabled() {
            properties.setEnabled(false);
            assertFalse(properties.isEnabled());

            properties.setEnabled(true);
            assertTrue(properties.isEnabled());
        }

        @Test
        @DisplayName("Should set and get infrastructure properties")
        void shouldSetAndGetInfrastructureProperties() {
            InfrastructureProperties infrastructure = new InfrastructureProperties();
            properties.setInfrastructures(infrastructure);
            assertSame(infrastructure, properties.getInfrastructures());
        }

        @Test
        @DisplayName("Should set and get capabilities properties")
        void shouldSetAndGetCapabilitiesProperties() {
            CapabilitiesProperties capabilities = new CapabilitiesProperties();
            properties.setCapabilities(capabilities);
            assertSame(capabilities, properties.getCapabilities());
        }
    }

    @Nested
    @DisplayName("Infrastructure Properties Tests")
    class InfrastructurePropertiesTests {

        private InfrastructureProperties infrastructureProperties;

        @BeforeEach
        void setUp() {
            infrastructureProperties = new InfrastructureProperties();
        }

        @Test
        @DisplayName("Should initialize trust domain")
        void shouldInitializeTrustDomain() {
            assertNotNull(infrastructureProperties.getTrustDomain());
        }

        @Test
        @DisplayName("Should set and get trust domain")
        void shouldSetAndGetTrustDomain() {
            infrastructureProperties.setTrustDomain("wimse://custom.domain");
            assertEquals("wimse://custom.domain", infrastructureProperties.getTrustDomain());
        }
    }

    @Nested
    @DisplayName("CapabilitiesProperties Tests")
    class CapabilitiesPropertiesTests {

        private CapabilitiesProperties capabilitiesProperties;

        @BeforeEach
        void setUp() {
            capabilitiesProperties = new CapabilitiesProperties();
        }

        @Test
        @DisplayName("Should initialize workload identity properties")
        void shouldInitializeWorkloadIdentityProperties() {
            assertNotNull(capabilitiesProperties.getWorkloadIdentity());
        }

        @Test
        @DisplayName("Should set and get workload identity properties")
        void shouldSetAndGetWorkloadIdentityProperties() {
            WorkloadIdentityProperties workloadIdentity = new WorkloadIdentityProperties();
            capabilitiesProperties.setWorkloadIdentity(workloadIdentity);
            assertSame(workloadIdentity, capabilitiesProperties.getWorkloadIdentity());
        }
    }

    @Nested
    @DisplayName("Boundary Conditions and Null Handling Tests")
    class BoundaryConditionsAndNullHandlingTests {

        @Test
        @DisplayName("Should handle null for all nested properties")
        void shouldHandleNullForAllNestedProperties() {
            properties.setInfrastructures(null);
            properties.setCapabilities(null);

            assertNull(properties.getInfrastructures());
            assertNull(properties.getCapabilities());
        }

        @Test
        @DisplayName("Should create independent instances")
        void shouldCreateIndependentInstances() {
            OpenAgentAuthProperties properties1 = new OpenAgentAuthProperties();
            OpenAgentAuthProperties properties2 = new OpenAgentAuthProperties();

            properties1.setEnabled(false);

            assertTrue(properties2.isEnabled());
        }
    }
}
