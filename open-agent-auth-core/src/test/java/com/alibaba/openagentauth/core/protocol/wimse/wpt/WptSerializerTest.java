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

import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WptSerializer}.
 */
@DisplayName("WPT Serializer Tests")
class WptSerializerTest {

    private OctetKeyPair signingKey;
    private WorkloadProofToken testWpt;

    @BeforeEach
    void setUp() throws JOSEException {
        signingKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("test-key-id")
                .generate();

        testWpt = createTestWpt();
    }

    @Nested
    @DisplayName("Successful Serialization Tests")
    class SuccessfulSerializationTests {

        @Test
        @DisplayName("Should serialize WPT with required claims")
        void shouldSerializeWptWithRequiredClaims() throws JOSEException {
            String jwtString = WptSerializer.serialize(testWpt, new Ed25519Signer(signingKey));

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
            assertThat(jwtString).matches("^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$");
        }

        @Test
        @DisplayName("Should produce valid JWT structure")
        void shouldProduceValidJwtStructure() throws JOSEException {
            String jwtString = WptSerializer.serialize(testWpt, new Ed25519Signer(signingKey));

            String[] parts = jwtString.split("\\.");
            assertThat(parts).hasSize(3);
            assertThat(parts[0]).isNotEmpty();
            assertThat(parts[1]).isNotEmpty();
            assertThat(parts[2]).isNotEmpty();
        }

        @Test
        @DisplayName("Should serialize WPT with audience")
        void shouldSerializeWptWithAudience() throws JOSEException {
            WorkloadProofToken wptWithAudience = createTestWptWithAudience();

            String jwtString = WptSerializer.serialize(wptWithAudience, new Ed25519Signer(signingKey));

            assertThat(jwtString).isNotNull();
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"aud\":\"https://api.example.com\"");
        }

        @Test
        @DisplayName("Should serialize WPT with access token hash")
        void shouldSerializeWptWithAccessTokenHash() throws JOSEException {
            WorkloadProofToken wptWithAth = createTestWptWithAccessTokenHash();

            String jwtString = WptSerializer.serialize(wptWithAth, new Ed25519Signer(signingKey));

            assertThat(jwtString).isNotNull();
            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"ath\"");
        }
    }

    @Nested
    @DisplayName("Parameter Validation Tests")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when WPT is null")
        void shouldThrowExceptionWhenWptIsNull() {
            assertThatThrownBy(() -> WptSerializer.serialize(null, new Ed25519Signer(signingKey)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WorkloadProofToken");
        }

        @Test
        @DisplayName("Should throw exception when signer is null")
        void shouldThrowExceptionWhenSignerIsNull() {
            assertThatThrownBy(() -> WptSerializer.serialize(testWpt, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("JWSSigner");
        }
    }

    @Nested
    @DisplayName("JWT Claims Tests")
    class JwtClaimsTests {

        @Test
        @DisplayName("Should include expiration claim")
        void shouldIncludeExpirationClaim() throws JOSEException {
            String jwtString = WptSerializer.serialize(testWpt, new Ed25519Signer(signingKey));

            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"exp\"");
        }

        @Test
        @DisplayName("Should include JWT ID claim")
        void shouldIncludeJwtIdClaim() throws JOSEException {
            String jwtString = WptSerializer.serialize(testWpt, new Ed25519Signer(signingKey));

            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"jti\"");
        }

        @Test
        @DisplayName("Should include workload token hash claim")
        void shouldIncludeWorkloadTokenHashClaim() throws JOSEException {
            String jwtString = WptSerializer.serialize(testWpt, new Ed25519Signer(signingKey));

            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"wth\"");
        }
    }

    @Nested
    @DisplayName("JWT Header Tests")
    class JwtHeaderTests {

        @Test
        @DisplayName("Should include EdDSA algorithm in header")
        void shouldIncludeAlgorithmInHeader() throws JOSEException {
            String jwtString = WptSerializer.serialize(testWpt, new Ed25519Signer(signingKey));

            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).contains("\"alg\":\"EdDSA\"");
        }

        @Test
        @DisplayName("Should include type in header")
        void shouldIncludeTypeInHeader() throws JOSEException {
            String jwtString = WptSerializer.serialize(testWpt, new Ed25519Signer(signingKey));

            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).contains("\"typ\":\"wpt+jwt\"");
        }
    }

    private WorkloadProofToken createTestWpt() {
        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .jwtId("test-jti-001")
                .workloadTokenHash("test-wth-hash")
                .build();

        return WorkloadProofToken.builder()
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wpt.jwt.string")
                .build();
    }

    private WorkloadProofToken createTestWptWithAudience() {
        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .audience("https://api.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .jwtId("test-jti-001")
                .workloadTokenHash("test-wth-hash")
                .build();

        return WorkloadProofToken.builder()
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wpt.jwt.string")
                .build();
    }

    private WorkloadProofToken createTestWptWithAccessTokenHash() {
        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .jwtId("test-jti-001")
                .workloadTokenHash("test-wth-hash")
                .accessTokenHash("test-ath-hash")
                .build();

        return WorkloadProofToken.builder()
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.wpt.jwt.string")
                .build();
    }
}
