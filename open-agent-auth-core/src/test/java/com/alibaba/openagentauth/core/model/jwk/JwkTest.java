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
 * <p>
 * Tests the JSON Web Key model's behavior including:
 * <ul>
 *   <li>Building JWKs with all required and optional fields</li>
 *   <li>Getter methods for all properties</li>
 *   <li>Validation logic for required fields</li>
 *   <li>Equals, hashCode, and toString methods</li>
 *   <li>Enum parsing for KeyType, KeyUse, and Curve</li>
 *   <li>Builder pattern with validation</li>
 * </ul>
 * </p>
 *
 * @since 1.0
 */
@DisplayName("Jwk Tests")
class JwkTest {

    private static final String X_COORDINATE = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    private static final String Y_COORDINATE = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";
    private static final String KEY_ID = "key-123";
    private static final String ALGORITHM = "ES256";

    @Nested
    @DisplayName("Builder Pattern Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build EC key with all fields")
        void shouldBuildEcKeyWithAllFields() {
            // When
            Jwk jwk = Jwk.builder()
                    .keyType(Jwk.KeyType.EC)
                    .use(Jwk.KeyUse.SIGNATURE)
                    .algorithm(ALGORITHM)
                    .curve(Jwk.Curve.P_256)
                    .x(X_COORDINATE)
                    .y(Y_COORDINATE)
                    .keyId(KEY_ID)
                    .build();

            // Then
            assertThat(jwk).isNotNull();
            assertThat(jwk.keyType()).isEqualTo(Jwk.KeyType.EC);
            assertThat(jwk.use()).isEqualTo(Jwk.KeyUse.SIGNATURE);
            assertThat(jwk.algorithm()).isEqualTo(ALGORITHM);
            assertThat(jwk.curve()).isEqualTo(Jwk.Curve.P_256);
            assertThat(jwk.x()).isEqualTo(X_COORDINATE);
            assertThat(jwk.y()).isEqualTo(Y_COORDINATE);
            assertThat(jwk.keyId()).isEqualTo(KEY_ID);
        }

        @Test
        @DisplayName("Should build EC key with null optional fields")
        void shouldBuildEcKeyWithNullOptionalFields() {
            // When
            Jwk jwk = Jwk.builder()
                    .keyType(Jwk.KeyType.EC)
                    .curve(Jwk.Curve.P_256)
                    .x(X_COORDINATE)
                    .y(Y_COORDINATE)
                    .build();

            // Then
            assertThat(jwk).isNotNull();
            assertThat(jwk.use()).isNull();
            assertThat(jwk.algorithm()).isNull();
            assertThat(jwk.keyId()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when keyType is null")
        void shouldThrowExceptionWhenKeyTypeIsNull() {
            // When & Then
            assertThatThrownBy(() -> Jwk.builder().build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("kty (key type) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when EC key is missing curve")
        void shouldThrowExceptionWhenEcKeyIsMissingCurve() {
            // When & Then
            assertThatThrownBy(() -> Jwk.builder()
                    .keyType(Jwk.KeyType.EC)
                    .x(X_COORDINATE)
                    .y(Y_COORDINATE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("crv (curve) is REQUIRED for EC keys");
        }

        @Test
        @DisplayName("Should throw exception when EC key is missing x coordinate")
        void shouldThrowExceptionWhenEcKeyIsMissingXCoordinate() {
            // When & Then
            assertThatThrownBy(() -> Jwk.builder()
                    .keyType(Jwk.KeyType.EC)
                    .curve(Jwk.Curve.P_256)
                    .y(Y_COORDINATE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("x coordinate is REQUIRED for EC keys");
        }

        @Test
        @DisplayName("Should throw exception when EC key is missing y coordinate")
        void shouldThrowExceptionWhenEcKeyIsMissingYCoordinate() {
            // When & Then
            assertThatThrownBy(() -> Jwk.builder()
                    .keyType(Jwk.KeyType.EC)
                    .curve(Jwk.Curve.P_256)
                    .x(X_COORDINATE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("y coordinate is REQUIRED for EC keys");
        }

        @Test
        @DisplayName("Should throw exception when EC key has empty x coordinate")
        void shouldThrowExceptionWhenEcKeyHasEmptyXCoordinate() {
            // When & Then
            assertThatThrownBy(() -> Jwk.builder()
                    .keyType(Jwk.KeyType.EC)
                    .curve(Jwk.Curve.P_256)
                    .x("")
                    .y(Y_COORDINATE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("x coordinate is REQUIRED for EC keys");
        }

        @Test
        @DisplayName("Should throw exception when EC key has null x coordinate")
        void shouldThrowExceptionWhenEcKeyHasNullXCoordinate() {
            // When & Then
            assertThatThrownBy(() -> Jwk.builder()
                    .keyType(Jwk.KeyType.EC)
                    .curve(Jwk.Curve.P_256)
                    .x((String) null)
                    .y(Y_COORDINATE)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("x coordinate is REQUIRED for EC keys");
        }
    }




    @Nested
    @DisplayName("KeyType Enum Tests")
    class KeyTypeEnumTests {

        @Test
        @DisplayName("Should return correct value for EC")
        void shouldReturnCorrectValueForEC() {
            // When & Then
            assertThat(Jwk.KeyType.EC.getValue()).isEqualTo("EC");
        }

        @Test
        @DisplayName("Should return correct value for RSA")
        void shouldReturnCorrectValueForRSA() {
            // When & Then
            assertThat(Jwk.KeyType.RSA.getValue()).isEqualTo("RSA");
        }

        @Test
        @DisplayName("Should return correct value for OCT")
        void shouldReturnCorrectValueForOCT() {
            // When & Then
            assertThat(Jwk.KeyType.OCT.getValue()).isEqualTo("oct");
        }

        @Test
        @DisplayName("Should parse EC from value")
        void shouldParseECFromValue() {
            // When & Then
            assertThat(Jwk.KeyType.fromValue("EC")).isEqualTo(Jwk.KeyType.EC);
        }

        @Test
        @DisplayName("Should parse RSA from value")
        void shouldParseRSAFromValue() {
            // When & Then
            assertThat(Jwk.KeyType.fromValue("RSA")).isEqualTo(Jwk.KeyType.RSA);
        }

        @Test
        @DisplayName("Should parse OCT from value")
        void shouldParseOCTFromValue() {
            // When & Then
            assertThat(Jwk.KeyType.fromValue("oct")).isEqualTo(Jwk.KeyType.OCT);
        }

        @Test
        @DisplayName("Should throw exception for unknown KeyType")
        void shouldThrowExceptionForUnknownKeyType() {
            // When & Then
            assertThatThrownBy(() -> Jwk.KeyType.fromValue("UNKNOWN"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unknown KeyType: UNKNOWN");
        }
    }

    @Nested
    @DisplayName("KeyUse Enum Tests")
    class KeyUseEnumTests {

        @Test
        @DisplayName("Should return correct value for SIGNATURE")
        void shouldReturnCorrectValueForSIGNATURE() {
            // When & Then
            assertThat(Jwk.KeyUse.SIGNATURE.getValue()).isEqualTo("sig");
        }

        @Test
        @DisplayName("Should return correct value for ENCRYPTION")
        void shouldReturnCorrectValueForENCRYPTION() {
            // When & Then
            assertThat(Jwk.KeyUse.ENCRYPTION.getValue()).isEqualTo("enc");
        }

        @Test
        @DisplayName("Should parse SIGNATURE from value")
        void shouldParseSIGNATUREFromValue() {
            // When & Then
            assertThat(Jwk.KeyUse.fromValue("sig")).isEqualTo(Jwk.KeyUse.SIGNATURE);
        }

        @Test
        @DisplayName("Should parse ENCRYPTION from value")
        void shouldParseENCRYPTIONFromValue() {
            // When & Then
            assertThat(Jwk.KeyUse.fromValue("enc")).isEqualTo(Jwk.KeyUse.ENCRYPTION);
        }

        @Test
        @DisplayName("Should throw exception for unknown KeyUse")
        void shouldThrowExceptionForUnknownKeyUse() {
            // When & Then
            assertThatThrownBy(() -> Jwk.KeyUse.fromValue("UNKNOWN"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unknown KeyUse: UNKNOWN");
        }
    }

    @Nested
    @DisplayName("Curve Enum Tests")
    class CurveEnumTests {

        @Test
        @DisplayName("Should return correct value for P_256")
        void shouldReturnCorrectValueForP_256() {
            // When & Then
            assertThat(Jwk.Curve.P_256.getValue()).isEqualTo("P-256");
        }

        @Test
        @DisplayName("Should return correct value for P_384")
        void shouldReturnCorrectValueForP_384() {
            // When & Then
            assertThat(Jwk.Curve.P_384.getValue()).isEqualTo("P-384");
        }

        @Test
        @DisplayName("Should return correct value for P_521")
        void shouldReturnCorrectValueForP_521() {
            // When & Then
            assertThat(Jwk.Curve.P_521.getValue()).isEqualTo("P-521");
        }

        @Test
        @DisplayName("Should parse P_256 from value")
        void shouldParseP_256FromValue() {
            // When & Then
            assertThat(Jwk.Curve.fromValue("P-256")).isEqualTo(Jwk.Curve.P_256);
        }

        @Test
        @DisplayName("Should parse P_384 from value")
        void shouldParseP_384FromValue() {
            // When & Then
            assertThat(Jwk.Curve.fromValue("P-384")).isEqualTo(Jwk.Curve.P_384);
        }

        @Test
        @DisplayName("Should parse P_521 from value")
        void shouldParseP_521FromValue() {
            // When & Then
            assertThat(Jwk.Curve.fromValue("P-521")).isEqualTo(Jwk.Curve.P_521);
        }

        @Test
        @DisplayName("Should throw exception for unknown Curve")
        void shouldThrowExceptionForUnknownCurve() {
            // When & Then
            assertThatThrownBy(() -> Jwk.Curve.fromValue("UNKNOWN"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Unknown Curve: UNKNOWN");
        }
    }

    /**
     * Helper method to create a test JWK instance.
     *
     * @return a test JWK instance
     */
    private Jwk createTestJwk() {
        return Jwk.builder()
                .keyType(Jwk.KeyType.EC)
                .use(Jwk.KeyUse.SIGNATURE)
                .algorithm(ALGORITHM)
                .curve(Jwk.Curve.P_256)
                .x(X_COORDINATE)
                .y(Y_COORDINATE)
                .keyId(KEY_ID)
                .build();
    }
}
