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
package com.alibaba.openagentauth.core.model.jwk;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Minimal Ed25519 JSON Web Key as used in AAP CT cnf.jwk and DPoP header.jwk.
 * <p>
 * Per spec §3 only Ed25519 ({@code kty=OKP}, {@code crv=Ed25519}) is permitted,
 * so those fields are wire-only constants emitted by {@link
 * com.alibaba.openagentauth.core.token.common.JwkConverter} and not carried on
 * the record itself.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8037">RFC 8037</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Jwk(
        @JsonProperty("x") String x,
        @JsonProperty("kid") String keyId) {

    public Jwk {
        if (ValidationUtils.isNullOrEmpty(x)) {
            throw new IllegalStateException("x coordinate is REQUIRED");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String x;
        private String keyId;

        public Builder x(String x)         { this.x     = x;     return this; }
        public Builder keyId(String keyId) { this.keyId = keyId; return this; }

        public Jwk build() {
            return new Jwk(x, keyId);
        }
    }
}
