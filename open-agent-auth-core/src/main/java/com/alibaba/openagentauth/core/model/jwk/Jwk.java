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
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * JSON Web Key (JWK) as defined in RFC 7517.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Jwk(
        @JsonProperty("kty") KeyType keyType,
        @JsonProperty("use") KeyUse use,
        @JsonProperty("alg") String algorithm,
        @JsonProperty("crv") Curve curve,
        @JsonProperty("x") String x,
        @JsonProperty("y") String y,
        @JsonProperty("kid") String keyId) {

    public Jwk {
        if (keyType == null) {
            throw new IllegalStateException("kty (key type) is REQUIRED");
        }
        if (keyType == KeyType.EC) {
            if (curve == null) {
                throw new IllegalStateException("crv (curve) is REQUIRED for EC keys");
            }
            if (ValidationUtils.isNullOrEmpty(x)) {
                throw new IllegalStateException("x coordinate is REQUIRED for EC keys");
            }
            if (ValidationUtils.isNullOrEmpty(y)) {
                throw new IllegalStateException("y coordinate is REQUIRED for EC keys");
            }
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    public enum KeyType {
        EC("EC"), RSA("RSA"), OCT("oct");

        private final String value;

        KeyType(String value) { this.value = value; }

        @JsonValue
        public String getValue() { return value; }

        public static KeyType fromValue(String value) {
            for (KeyType type : values()) {
                if (type.value.equals(value)) return type;
            }
            throw new IllegalArgumentException("Unknown KeyType: " + value);
        }
    }

    public enum KeyUse {
        SIGNATURE("sig"), ENCRYPTION("enc");

        private final String value;

        KeyUse(String value) { this.value = value; }

        @JsonValue
        public String getValue() { return value; }

        public static KeyUse fromValue(String value) {
            for (KeyUse keyUse : values()) {
                if (keyUse.value.equals(value)) return keyUse;
            }
            throw new IllegalArgumentException("Unknown KeyUse: " + value);
        }
    }

    public enum Curve {
        P_256("P-256"), P_384("P-384"), P_521("P-521");

        private final String value;

        Curve(String value) { this.value = value; }

        @JsonValue
        public String getValue() { return value; }

        public static Curve fromValue(String value) {
            for (Curve curve : values()) {
                if (curve.value.equals(value)) return curve;
            }
            throw new IllegalArgumentException("Unknown Curve: " + value);
        }
    }

    public static class Builder {
        private KeyType keyType;
        private KeyUse use;
        private String algorithm;
        private Curve curve;
        private String x;
        private String y;
        private String keyId;

        public Builder keyType(KeyType keyType)  { this.keyType  = keyType;  return this; }
        public Builder use(KeyUse use)            { this.use      = use;      return this; }
        public Builder algorithm(String algorithm){ this.algorithm = algorithm; return this; }
        public Builder curve(Curve curve)         { this.curve    = curve;    return this; }
        public Builder x(String x)                { this.x        = x;        return this; }
        public Builder y(String y)                { this.y        = y;        return this; }
        public Builder keyId(String keyId)        { this.keyId    = keyId;    return this; }

        public Jwk build() {
            return new Jwk(keyType, use, algorithm, curve, x, y, keyId);
        }
    }
}
