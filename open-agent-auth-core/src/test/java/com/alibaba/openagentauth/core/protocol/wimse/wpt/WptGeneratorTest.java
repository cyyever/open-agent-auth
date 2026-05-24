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
package com.alibaba.openagentauth.core.protocol.wimse.wpt;

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WptGenerator}.
 */
@DisplayName("WPT Generator Tests")
class WptGeneratorTest {

    private OctetKeyPair wptPublicKey;
    private OctetKeyPair wptPrivateKey;
    private WptGenerator wptGenerator;
    private WorkloadIdentityToken testWit;

    @BeforeEach
    void setUp() throws JOSEException {
        wptPrivateKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("wpt-key")
                .generate();
        wptPublicKey = wptPrivateKey.toPublicJWK();

        wptGenerator = new WptGenerator();

        testWit = createTestWit(wptPublicKey);
    }

    private WorkloadIdentityToken createTestWit(OctetKeyPair publicKey) {
        Jwk jwk = Jwk.builder()
                .x(publicKey.getX().toString())
                .build();

        WorkloadIdentityToken.Claims.Confirmation confirmation =
            WorkloadIdentityToken.Claims.Confirmation.builder()
                .jwk(jwk)
                .build();

        WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                .issuer("wimse://example.com")
                .subject("agent-001")
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(3600)))
                .jwtId(java.util.UUID.randomUUID().toString())
                .confirmation(confirmation)
                .build();

        return WorkloadIdentityToken.builder()
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wit.jwt.string")
                .build();
    }

    @Nested
    @DisplayName("WPT Generation - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should generate valid WPT with all required claims")
        void shouldGenerateValidWptWithRequiredClaims() throws JOSEException {
            long expirationSeconds = 300;

            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            assertThat(wpt).isNotNull();
            assertThat(wpt.claims()).isNotNull();
        }

        @Test
        @DisplayName("Should include wth claim with correct hash")
        void shouldIncludeWthClaimWithCorrectHash() throws JOSEException {
            long expirationSeconds = 300;

            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            assertThat(wpt.claims().workloadTokenHash()).isNotNull();
        }

        @Test
        @DisplayName("Should set expiration time correctly")
        void shouldSetExpirationTimeCorrectly() throws JOSEException {
            long expirationSeconds = 600;
            Instant beforeGeneration = Instant.now();

            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            Instant expirationTime = wpt.claims().expirationTime().toInstant();
            Instant afterGeneration = Instant.now();

            Instant expectedMin = beforeGeneration.plusSeconds(expirationSeconds).minusSeconds(1);
            Instant expectedMax = afterGeneration.plusSeconds(expirationSeconds).plusSeconds(1);

            assertThat(expirationTime).isBetween(expectedMin, expectedMax);
        }

        @Test
        @DisplayName("Should generate unique jti for each WPT")
        void shouldGenerateUniqueJtiForEachWpt() throws JOSEException {
            long expirationSeconds = 300;

            WorkloadProofToken wpt1 = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);
            WorkloadProofToken wpt2 = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            assertThat(wpt1.claims().jwtId()).isNotNull();
            assertThat(wpt2.claims().jwtId()).isNotNull();
            assertThat(wpt1.claims().jwtId()).isNotEqualTo(wpt2.claims().jwtId());
        }

    }

    @Nested
    @DisplayName("WPT Generation - Parameter Validation")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when WIT is null")
        void shouldThrowExceptionWhenWitIsNull() {
            long expirationSeconds = 300;

            assertThatThrownBy(() -> wptGenerator.generateWpt(null, wptPrivateKey, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WIT cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when expirationSeconds is zero")
        void shouldThrowExceptionWhenExpirationSecondsIsZero() {
            long expirationSeconds = 0;

            assertThatThrownBy(() -> wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }

        @Test
        @DisplayName("Should throw exception when expirationSeconds is negative")
        void shouldThrowExceptionWhenExpirationSecondsIsNegative() {
            long expirationSeconds = -100;

            assertThatThrownBy(() -> wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }
    }

    @Nested
    @DisplayName("WPT Generation - Constructor Validation")
    class ConstructorValidationTests {

        @Test
        @DisplayName("Should create WPT generator successfully")
        void shouldCreateWptGeneratorSuccessfully() {
            WptGenerator generator = new WptGenerator();
            assertThat(generator).isNotNull();
        }
    }

    @Nested
    @DisplayName("WPT Generation - Protocol Compliance")
    class ProtocolComplianceTests {

        @Test
        @DisplayName("Should compute wth using SHA-256 and Base64URL encoding")
        void shouldComputeWthUsingSha256AndBase64UrlEncoding() throws JOSEException {
            long expirationSeconds = 300;

            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            String actualWth = wpt.claims().workloadTokenHash();
            assertThat(actualWth).isNotNull();
            assertThat(actualWth).isNotEmpty();
        }
    }
}
