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
package com.alibaba.openagentauth.core.exception;

/**
 * Interface for Core module error codes.
 * Error code format: {@code OPEN_AGENT_AUTH_10_YYZZ} (system 10, YY=domain, ZZ=error).
 *
 * @since 1.0
 */
public interface CoreErrorCode extends ErrorCode {

    /**
     * System code for Core module.
     */
    String SYSTEM_CODE = "10";

    /**
     * Domain code for OIDC.
     */
    String DOMAIN_CODE_OIDC = "01";

    /**
     * Domain code for Audit.
     */
    String DOMAIN_CODE_AUDIT = "02";

    /**
     * Domain code for Crypto.
     */
    String DOMAIN_CODE_CRYPTO = "03";

    /**
     * Domain code for OAuth2.
     */
    String DOMAIN_CODE_OAUTH2 = "04";

    /**
     * Domain code for Policy.
     */
    String DOMAIN_CODE_POLICY = "05";

    /**
     * Domain code for Workload.
     */
    String DOMAIN_CODE_WORKLOAD = "06";

    /**
     * Domain code for Binding.
     */
    String DOMAIN_CODE_BINDING = "07";

    @Override
    default String getSystemCode() {
        return SYSTEM_CODE;
    }
}