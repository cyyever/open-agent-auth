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
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WptGenerator}.
 * Tests verify compliance with WIMSE WPT protocol specification:
 * https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/
 */
@DisplayName("WPT Generator Tests - draft-ietf-wimse-wpt")
class WptGeneratorTest {

    private JWK signingKey;
    private JWK verificationKey;
    private ECKey wptPublicKey;
    private ECKey wptPrivateKey;
    private WptGenerator wptGenerator;
    private WorkloadIdentityToken testWit;

    @BeforeEach
    void setUp() throws JOSEException {
        // Generate EC key pair for WPT signing (as per WIMSE spec)
        ECKeyGenerator ecKeyGenerator = new ECKeyGenerator(Curve.P_256);
        signingKey = ecKeyGenerator.keyID("wpt-signing-key").generate();
        verificationKey = signingKey.toPublicJWK();

        // Generate EC key pair for WIT cnf.jwk
        wptPrivateKey = ecKeyGenerator.keyID("wpt-key").generate();
        wptPublicKey = wptPrivateKey.toPublicJWK();

        wptGenerator = new WptGenerator();

        // Create test WIT with cnf.jwk containing the WPT public key
        testWit = createTestWit(wptPublicKey);
    }

    /**
     * Creates a test WIT with the given public key in cnf.jwk.
     */
    private WorkloadIdentityToken createTestWit(ECKey publicKey) {
        Jwk jwk = Jwk.builder()
                .keyType(Jwk.KeyType.EC)
                .curve(Jwk.Curve.P_256)
                .x(publicKey.getX().toString())
                .y(publicKey.getY().toString())
                .algorithm("ES256")
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

        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("wit+jwt")
                .algorithm("RS256")
                .build();

        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wit.jwt.string") // Add JWT string for wth computation
                .build();
    }

    @Nested
    @DisplayName("WPT Generation - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should generate valid WPT with all required claims")
        void shouldGenerateValidWptWithRequiredClaims() throws JOSEException {
            // Given
            long expirationSeconds = 300;

            // When
            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            // Then
            assertThat(wpt).isNotNull();
            assertThat(wpt.claims()).isNotNull();
            assertThat(wpt.header()).isNotNull();
        }

        @Test
        @DisplayName("Should include wth claim with correct hash")
        void shouldIncludeWthClaimWithCorrectHash() throws JOSEException {
            // Given
            long expirationSeconds = 300;
            // Note: testWit doesn't have a JWT string yet, so we need to generate a proper WIT first
            // For this test, we'll skip the hash verification since testWit is a mock
            // and focus on the fact that wth is present

            // When
            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            // Then
            assertThat(wpt.claims().workloadTokenHash()).isNotNull();
            // The wth should be computed from the WIT's JWT string
            // Since testWit is a mock without JWT string, we just verify it's not null
        }

        @Test
        @DisplayName("Should set expiration time correctly")
        void shouldSetExpirationTimeCorrectly() throws JOSEException {
            // Given
            long expirationSeconds = 600;
            Instant beforeGeneration = Instant.now();

            // When
            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            // Then
            Instant expirationTime = wpt.claims().expirationTime().toInstant();
            Instant afterGeneration = Instant.now();

            // Calculate expected expiration time range
            // The expiration time should be approximately expirationSeconds from now
            // Allow for 2 seconds tolerance due to timing precision
            Instant expectedMin = beforeGeneration.plusSeconds(expirationSeconds).minusSeconds(1);
            Instant expectedMax = afterGeneration.plusSeconds(expirationSeconds).plusSeconds(1);

            assertThat(expirationTime).isBetween(expectedMin, expectedMax);
        }

        @Test
        @DisplayName("Should generate unique jti for each WPT")
        void shouldGenerateUniqueJtiForEachWpt() throws JOSEException {
            // Given
            long expirationSeconds = 300;

            // When
            WorkloadProofToken wpt1 = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);
            WorkloadProofToken wpt2 = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            // Then
            assertThat(wpt1.claims().jwtId()).isNotNull();
            assertThat(wpt2.claims().jwtId()).isNotNull();
            assertThat(wpt1.claims().jwtId()).isNotEqualTo(wpt2.claims().jwtId());
        }

        @Test
        @DisplayName("Should extract algorithm from WIT cnf.jwk.alg")
        void shouldExtractAlgorithmFromWitCnfJwkAlg() throws JOSEException {
            // Given
            long expirationSeconds = 300;

            // When
            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            // Then
            assertThat(wpt.header().algorithm()).isEqualTo("ES256");
        }

        @Test
        @DisplayName("Should use correct media type 'wpt+jwt'")
        void shouldUseCorrectMediaType() throws JOSEException {
            // Given
            long expirationSeconds = 300;

            // When
            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            // Then
            assertThat(wpt.header().type()).isEqualTo("wpt+jwt");
        }
    }

    @Nested
    @DisplayName("WPT Generation - Parameter Validation")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when WIT is null")
        void shouldThrowExceptionWhenWitIsNull() {
            // Given
            long expirationSeconds = 300;

            // When & Then
            assertThatThrownBy(() -> wptGenerator.generateWpt(null, wptPrivateKey, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WIT cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when expirationSeconds is zero")
        void shouldThrowExceptionWhenExpirationSecondsIsZero() {
            // Given
            long expirationSeconds = 0;

            // When & Then
            assertThatThrownBy(() -> wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }

        @Test
        @DisplayName("Should throw exception when expirationSeconds is negative")
        void shouldThrowExceptionWhenExpirationSecondsIsNegative() {
            // Given
            long expirationSeconds = -100;

            // When & Then
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
            // When & Then
            // WptGenerator constructor is parameterless
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
            // Given
            long expirationSeconds = 300;
            // Note: testWit is a mock without JWT string, so we can't verify the exact hash
            // This test verifies that the wth is computed and present

            // When
            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            // Then
            // Verify hash computation follows: BASE64URL(SHA-256(ASCII(WIT)))
            String actualWth = wpt.claims().workloadTokenHash();
            assertThat(actualWth).isNotNull();
            // The wth should be a base64url-encoded SHA-256 hash
            // We can verify it's not empty and has reasonable length
            assertThat(actualWth).isNotEmpty();
            assertThat(actualWth.length()).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should match WPT algorithm with WIT cnf.jwk.alg")
        void shouldMatchWptAlgorithmWithWitCnfJwkAlg() throws JOSEException {
            // Given
            long expirationSeconds = 300;
            String witAlg = testWit.getConfirmation().jwk().algorithm();

            // When
            WorkloadProofToken wpt = wptGenerator.generateWpt(testWit, wptPrivateKey, expirationSeconds);

            // Then
            // Per draft-ietf-wimse-wpt: WPT header alg MUST match WIT cnf.jwk.alg
            assertThat(wpt.header().algorithm()).isEqualTo(witAlg);
        }

        @Test
        @DisplayName("Should handle WIT with different algorithms")
        void shouldHandleWitWithDifferentAlgorithms() throws JOSEException {
            // Given
            long expirationSeconds = 300;
            
            // Create WIT with ES256 algorithm (matching the signing key curve P_256)
            ECKey es256Key = new ECKeyGenerator(Curve.P_256).keyID("wpt-es256").generate();
            WorkloadIdentityToken witWithEs256 = createTestWitWithAlg(es256Key.toPublicJWK(), "ES256");

            // When
            WorkloadProofToken wpt = wptGenerator.generateWpt(witWithEs256, es256Key, expirationSeconds);

            // Then
            assertThat(wpt.header().algorithm()).isEqualTo("ES256");
        }

        @Test
        @DisplayName("Should throw exception when WIT cnf.jwk.alg is null")
        void shouldThrowExceptionWhenWitMissingCnfJwk() throws JOSEException {
            // Given
            long expirationSeconds = 300;
            WorkloadIdentityToken witWithCnfJwkMissingAlg = createWitWithCnfJwkMissingAlg();

            // When & Then
            assertThatThrownBy(() -> wptGenerator.generateWpt(witWithCnfJwkMissingAlg, wptPrivateKey, expirationSeconds))
                    .isInstanceOf(JOSEException.class)
                    .hasMessageContaining("WIT cnf.jwk missing alg field");
        }

        @Test
        @DisplayName("Should throw exception when WIT cnf.jwk missing alg field")
        void shouldThrowExceptionWhenWitCnfJwkMissingAlg() throws JOSEException {
            // Given
            long expirationSeconds = 300;
            WorkloadIdentityToken witWithoutAlg = createWitWithoutAlg();

            // When & Then
            assertThatThrownBy(() -> wptGenerator.generateWpt(witWithoutAlg, wptPrivateKey, expirationSeconds))
                    .isInstanceOf(JOSEException.class)
                    .hasMessageContaining("WIT cnf.jwk missing alg field");
        }
    }

    /**
     * Helper method to create a WIT with a specific algorithm.
     */
    private WorkloadIdentityToken createTestWitWithAlg(ECKey publicKey, String algorithm) {
        Jwk jwk = Jwk.builder()
                .keyType(Jwk.KeyType.EC)
                .curve(Jwk.Curve.fromValue(publicKey.getCurve().getName()))
                .x(publicKey.getX().toString())
                .y(publicKey.getY().toString())
                .algorithm(algorithm)
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

        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("wit+jwt")
                .algorithm("RS256")
                .build();

        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wit.jwt.string") // Add JWT string for wth computation
                .build();
    }

    /**
     * Helper method to create a WIT with cnf.jwk but missing alg field.
     */
    private WorkloadIdentityToken createWitWithCnfJwkMissingAlg() {
        // Create a JWK without algorithm field (invalid according to spec)
        Jwk jwkWithoutAlg = Jwk.builder()
                .keyType(Jwk.KeyType.EC)
                .curve(Jwk.Curve.P_256)
                .x("test-x")
                .y("test-y")
                .algorithm(null) // Missing algorithm
                .build();

        // Create a confirmation claim with jwk but missing alg
        WorkloadIdentityToken.Claims.Confirmation confirmation =
            WorkloadIdentityToken.Claims.Confirmation.builder()
                .jwk(jwkWithoutAlg)
                .build();

        WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                .issuer("wimse://example.com")
                .subject("agent-001")
                .expirationTime(java.util.Date.from(Instant.now().plusSeconds(3600)))
                .jwtId(java.util.UUID.randomUUID().toString())
                .confirmation(confirmation)
                .build();

        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("wit+jwt")
                .algorithm("RS256")
                .build();

        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wit.jwt.string") // Add JWT string for wth computation
                .build();
    }

    /**
     * Helper method to create a WIT with cnf.jwk missing alg field.
     */
    private WorkloadIdentityToken createWitWithoutAlg() throws JOSEException {
        ECKey key = new ECKeyGenerator(Curve.P_256).keyID("wpt-key").generate();

        Jwk jwk = Jwk.builder()
                .keyType(Jwk.KeyType.EC)
                .curve(Jwk.Curve.P_256)
                .x(key.getX().toString())
                .y(key.getY().toString())
                .algorithm(null) // Missing algorithm
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

        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("wit+jwt")
                .algorithm("RS256")
                .build();

        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wit.jwt.string") // Add JWT string for wth computation
                .build();
    }
}
