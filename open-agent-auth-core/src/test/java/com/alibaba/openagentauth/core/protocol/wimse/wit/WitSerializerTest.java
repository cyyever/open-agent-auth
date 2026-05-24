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
package com.alibaba.openagentauth.core.protocol.wimse.wit;

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("WIT Serializer Tests")
class WitSerializerTest {

    private OctetKeyPair signingKey;
    private WorkloadIdentityToken testWit;

    @BeforeEach
    void setUp() throws JOSEException {
        signingKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("test-key-id")
                .generate();

        testWit = createTestWit();
    }

    @Nested
    @DisplayName("Successful Serialization Tests")
    class SuccessfulSerializationTests {

        @Test
        @DisplayName("Should serialize WIT with required claims")
        void shouldSerializeWitWithRequiredClaims() throws JOSEException {
            String jwtString = WitSerializer.serialize(testWit, new Ed25519Signer(signingKey));

            assertThat(jwtString).isNotNull();
            assertThat(jwtString).isNotEmpty();
            assertThat(jwtString).matches("^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+$");
        }

        @Test
        @DisplayName("Should produce valid JWT structure")
        void shouldProduceValidJwtStructure() throws JOSEException {
            String jwtString = WitSerializer.serialize(testWit, new Ed25519Signer(signingKey));

            String[] parts = jwtString.split("\\.");
            assertThat(parts).hasSize(3);
            assertThat(parts[0]).isNotEmpty();
            assertThat(parts[1]).isNotEmpty();
            assertThat(parts[2]).isNotEmpty();
        }

        @Test
        @DisplayName("Should NOT include kid in header (AAP spec: header whitelist is {alg, typ})")
        void shouldNotIncludeKidInHeader() throws JOSEException {
            String jwtString = WitSerializer.serialize(testWit, new Ed25519Signer(signingKey));

            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).doesNotContain("\"kid\"");
        }

        @Test
        @DisplayName("Should serialize WIT with confirmation claim")
        void shouldSerializeWitWithConfirmationClaim() throws JOSEException {
            String jwtString = WitSerializer.serialize(testWit, new Ed25519Signer(signingKey));

            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"cnf\"");
            assertThat(payload).contains("\"jwk\"");
        }
    }

    @Nested
    @DisplayName("Parameter Validation Tests")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when WIT is null")
        void shouldThrowExceptionWhenWitIsNull() {
            assertThatThrownBy(() -> WitSerializer.serialize(null, new Ed25519Signer(signingKey)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WorkloadIdentityToken");
        }

        @Test
        @DisplayName("Should throw exception when signer is null")
        void shouldThrowExceptionWhenSignerIsNull() {
            assertThatThrownBy(() -> WitSerializer.serialize(testWit, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("JWSSigner");
        }
    }

    @Nested
    @DisplayName("JWT Claims Tests")
    class JwtClaimsTests {

        @Test
        @DisplayName("Should include issuer claim")
        void shouldIncludeIssuerClaim() throws JOSEException {
            String jwtString = WitSerializer.serialize(testWit, new Ed25519Signer(signingKey));

            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"iss\":\"https://issuer.example.com\"");
        }

        @Test
        @DisplayName("Should include subject claim")
        void shouldIncludeSubjectClaim() throws JOSEException {
            String jwtString = WitSerializer.serialize(testWit, new Ed25519Signer(signingKey));

            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"sub\":\"workload-001\"");
        }

        @Test
        @DisplayName("Should include expiration claim")
        void shouldIncludeExpirationClaim() throws JOSEException {
            String jwtString = WitSerializer.serialize(testWit, new Ed25519Signer(signingKey));

            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"exp\"");
        }

        @Test
        @DisplayName("Should include JWT ID claim")
        void shouldIncludeJwtIdClaim() throws JOSEException {
            String jwtString = WitSerializer.serialize(testWit, new Ed25519Signer(signingKey));

            String payload = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[1]));
            assertThat(payload).contains("\"jti\"");
        }
    }

    @Nested
    @DisplayName("JWT Header Tests")
    class JwtHeaderTests {

        @Test
        @DisplayName("Should include EdDSA algorithm in header")
        void shouldIncludeAlgorithmInHeader() throws JOSEException {
            String jwtString = WitSerializer.serialize(testWit, new Ed25519Signer(signingKey));

            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).contains("\"alg\":\"EdDSA\"");
        }

        @Test
        @DisplayName("Should include type in header")
        void shouldIncludeTypeInHeader() throws JOSEException {
            String jwtString = WitSerializer.serialize(testWit, new Ed25519Signer(signingKey));

            String header = new String(java.util.Base64.getUrlDecoder().decode(jwtString.split("\\.")[0]));
            assertThat(header).contains("\"typ\":\"wit+jwt\"");
        }
    }

    private WorkloadIdentityToken createTestWit() throws JOSEException {
        OctetKeyPair edKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("wpt-key")
                .generate();

        Jwk jwk = Jwk.builder()
                .keyType(Jwk.KeyType.OKP)
                .keyId("wpt-key")
                .curve(Jwk.Curve.Ed25519)
                .x(edKey.getX().toString())
                .build();

        WorkloadIdentityToken.Claims.Confirmation confirmation =
            WorkloadIdentityToken.Claims.Confirmation.builder()
                .jwk(jwk)
                .build();

        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("wit+jwt")
                .build();

        WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                .issuer("https://issuer.example.com")
                .subject("workload-001")
                .expirationTime(new java.util.Date(System.currentTimeMillis() + 3600000))
                .jwtId("test-jti-001")
                .confirmation(confirmation)
                .build();

        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claims)
                .signature("test-signature")
                .jwtString("test.jwt.string")
                .build();
    }
}
