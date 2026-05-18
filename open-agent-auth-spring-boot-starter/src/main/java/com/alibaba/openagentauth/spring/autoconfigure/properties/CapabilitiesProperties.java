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
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Capabilities configuration. Nested under {@code open-agent-auth.capabilities}.
 *
 * @since 1.0
 */
public class CapabilitiesProperties {

    @NestedConfigurationProperty
    private WorkloadIdentityProperties workloadIdentity = new WorkloadIdentityProperties();

    public WorkloadIdentityProperties getWorkloadIdentity() {
        return workloadIdentity;
    }

    public void setWorkloadIdentity(WorkloadIdentityProperties workloadIdentity) {
        this.workloadIdentity = workloadIdentity;
    }
}
