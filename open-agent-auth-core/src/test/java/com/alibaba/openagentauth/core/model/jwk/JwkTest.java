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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link Jwk}.
 *
 * @since 1.0
 */
@DisplayName("Jwk Tests")
class JwkTest {

    private static final String X_COORDINATE = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    private static final String KEY_ID = "key-123";

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build OKP key with all fields")
        void shouldBuildOkpKeyWithAllFields() {
            Jwk jwk = Jwk.builder()
                    .keyType(Jwk.KeyType.OKP)
                    .use(Jwk.KeyUse.SIGNATURE)
                    .curve(Jwk.Curve.Ed25519)
                    .x(X_COORDINATE)
                    .keyId(KEY_ID)
                    .build();

            assertThat(jwk).isNotNull();
            assertThat(jwk.keyType()).isEqualTo(Jwk.KeyType.OKP);
            assertThat(jwk.use()).isEqualTo(Jwk.KeyUse.SIGNATURE);
            assertThat(jwk.curve()).isEqualTo(Jwk.Curve.Ed25519);
            assertThat(jwk.x()).isEqualTo(X_COORDINATE);
            assertThat(jwk.keyId()).isEqualTo(KEY_ID);
        }

        @Test
        @DisplayName("Should build OKP key with null optional fields")
        void shouldBuildOkpKeyWithNullOptionalFields() {
            Jwk jwk = Jwk.builder()
                    .keyType(Jwk.KeyType.OKP)
                    .curve(Jwk.Curve.Ed25519)
                    .x(X_COORDINATE)
                    .build();

            assertThat(jwk).isNotNull();
            assertThat(jwk.use()).isNull();
            assertThat(jwk.keyId()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when keyType is null")
        void shouldThrowExceptionWhenKeyTypeIsNull() {
            assertThatThrownBy(() -> Jwk.builder().build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("kty (key type) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when curve is missing")
        void shouldThrowExceptionWhenCurveIsMissing() {
            assertThatThrownBy(() -> Jwk.builder()
                    .keyType(Jwk.KeyType.OKP)
                    .x(X_COORDINATE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("crv (curve) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when x coordinate is missing")
        void shouldThrowExceptionWhenXCoordinateIsMissing() {
            assertThatThrownBy(() -> Jwk.builder()
                    .keyType(Jwk.KeyType.OKP)
                    .curve(Jwk.Curve.Ed25519)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("x coordinate is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when x coordinate is empty")
        void shouldThrowExceptionWhenXCoordinateIsEmpty() {
            assertThatThrownBy(() -> Jwk.builder()
                    .keyType(Jwk.KeyType.OKP)
                    .curve(Jwk.Curve.Ed25519)
                    .x("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("x coordinate is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when x coordinate is null")
        void shouldThrowExceptionWhenXCoordinateIsNull() {
            assertThatThrownBy(() -> Jwk.builder()
                    .keyType(Jwk.KeyType.OKP)
                    .curve(Jwk.Curve.Ed25519)
                    .x((String) null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("x coordinate is REQUIRED");
        }
    }

    @Nested
    @DisplayName("KeyType Enum Tests")
    class KeyTypeEnumTests {

        @Test
        @DisplayName("Should return correct value for OKP")
        void shouldReturnCorrectValueForOKP() {
            assertThat(Jwk.KeyType.OKP.getValue()).isEqualTo("OKP");
        }

        @Test
        @DisplayName("Should parse OKP from value")
        void shouldParseOKPFromValue() {
            assertThat(Jwk.KeyType.fromValue("OKP")).isEqualTo(Jwk.KeyType.OKP);
        }

        @Test
        @DisplayName("Should throw exception for unknown KeyType")
        void shouldThrowExceptionForUnknownKeyType() {
            assertThatThrownBy(() -> Jwk.KeyType.fromValue("RSA"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unknown KeyType: RSA");
        }
    }

    @Nested
    @DisplayName("KeyUse Enum Tests")
    class KeyUseEnumTests {

        @Test
        @DisplayName("Should return correct value for SIGNATURE")
        void shouldReturnCorrectValueForSIGNATURE() {
            assertThat(Jwk.KeyUse.SIGNATURE.getValue()).isEqualTo("sig");
        }

        @Test
        @DisplayName("Should return correct value for ENCRYPTION")
        void shouldReturnCorrectValueForENCRYPTION() {
            assertThat(Jwk.KeyUse.ENCRYPTION.getValue()).isEqualTo("enc");
        }

        @Test
        @DisplayName("Should parse SIGNATURE from value")
        void shouldParseSIGNATUREFromValue() {
            assertThat(Jwk.KeyUse.fromValue("sig")).isEqualTo(Jwk.KeyUse.SIGNATURE);
        }

        @Test
        @DisplayName("Should parse ENCRYPTION from value")
        void shouldParseENCRYPTIONFromValue() {
            assertThat(Jwk.KeyUse.fromValue("enc")).isEqualTo(Jwk.KeyUse.ENCRYPTION);
        }

        @Test
        @DisplayName("Should throw exception for unknown KeyUse")
        void shouldThrowExceptionForUnknownKeyUse() {
            assertThatThrownBy(() -> Jwk.KeyUse.fromValue("UNKNOWN"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unknown KeyUse: UNKNOWN");
        }
    }

    @Nested
    @DisplayName("Curve Enum Tests")
    class CurveEnumTests {

        @Test
        @DisplayName("Should return correct value for Ed25519")
        void shouldReturnCorrectValueForEd25519() {
            assertThat(Jwk.Curve.Ed25519.getValue()).isEqualTo("Ed25519");
        }

        @Test
        @DisplayName("Should parse Ed25519 from value")
        void shouldParseEd25519FromValue() {
            assertThat(Jwk.Curve.fromValue("Ed25519")).isEqualTo(Jwk.Curve.Ed25519);
        }

        @Test
        @DisplayName("Should throw exception for unknown Curve")
        void shouldThrowExceptionForUnknownCurve() {
            assertThatThrownBy(() -> Jwk.Curve.fromValue("P-256"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unknown Curve: P-256");
        }
    }
}
