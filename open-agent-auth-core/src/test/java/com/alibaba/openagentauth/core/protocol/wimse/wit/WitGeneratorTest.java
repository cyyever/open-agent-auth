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

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link WitGenerator}.
 */
@DisplayName("WIT Generator Tests")
class WitGeneratorTest {

    private OctetKeyPair signingKey;
    private OctetKeyPair verificationKey;
    private TrustDomain trustDomain;
    private WitGenerator witGenerator;
    private String workloadId;
    private OctetKeyPair wptPublicKey;

    @BeforeEach
    void setUp() throws JOSEException {
        signingKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("wit-signing-key")
                .generate();
        verificationKey = signingKey.toPublicJWK();

        OctetKeyPair wptKeyPair = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID("wpt-key")
                .generate();
        wptPublicKey = wptKeyPair.toPublicJWK();

        trustDomain = new TrustDomain("wimse://example.com");
        witGenerator = new WitGenerator(signingKey, trustDomain);

        workloadId = "agent-001";
    }

    @Nested
    @DisplayName("WIT Generation - Happy Path")
    class HappyPathTests {

        @Test
        @DisplayName("Should generate valid WIT with all required claims")
        void shouldGenerateValidWitWithRequiredClaims() throws JOSEException, ParseException {
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            assertThat(wit).isNotNull();
            assertThat(wit.jwtString()).isNotNull();
            assertThat(wit.jwtString()).isNotEmpty();

            assertThat(wit.getSubject()).isEqualTo(workloadId);
            assertThat(wit.getIssuer()).isEqualTo(trustDomain.getDomainId());
            assertThat(wit.getExpirationTime()).isNotNull();
            assertThat(wit.getConfirmation()).isNotNull();
            assertThat(wit.getConfirmation().jwk()).isNotNull();
            assertThat(wit.getJwtId()).isNotNull();
        }

        @Test
        @DisplayName("Should set expiration time correctly")
        void shouldSetExpirationTimeCorrectly() throws JOSEException, ParseException {
            long expirationSeconds = 7200;
            String wptPublicKeyJson = wptPublicKey.toJSONString();
            Instant beforeGeneration = Instant.now();

            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            Instant expirationTime = wit.getExpirationTime().toInstant();

            Instant expectedMin = beforeGeneration.truncatedTo(ChronoUnit.SECONDS)
                    .plusSeconds(expirationSeconds);
            Instant expectedMax = beforeGeneration.truncatedTo(ChronoUnit.SECONDS)
                    .plusSeconds(expirationSeconds + 1);

            assertThat(expirationTime).isBetween(expectedMin, expectedMax);
        }

        @Test
        @DisplayName("Should generate unique jti for each WIT")
        void shouldGenerateUniqueJtiForEachWit() throws JOSEException, ParseException {
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            WorkloadIdentityToken wit1 = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);
            WorkloadIdentityToken wit2 = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            assertThat(wit1.getJwtId()).isNotNull();
            assertThat(wit2.getJwtId()).isNotNull();
            assertThat(wit1.getJwtId()).isNotEqualTo(wit2.getJwtId());
        }

        @Test
        @DisplayName("Should be verifiable by WitValidator")
        void shouldBeVerifiableByWitValidator() throws Exception {
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();
            String verificationKeyId = "test-verification-key";
            KeyManager mockKeyManager = mock(KeyManager.class);
            when(mockKeyManager.resolveVerificationKey(anyString())).thenReturn(verificationKey);
            WitValidator validator = new WitValidator(mockKeyManager, verificationKeyId, trustDomain);

            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);
            String witJwt = wit.jwtString();

            var result = validator.validate(witJwt);
            assertThat(result.isValid()).isTrue();
            assertThat(result.getToken()).isNotNull();
            assertThat(result.getToken().getSubject()).isEqualTo(workloadId);
        }
    }

    @Nested
    @DisplayName("WIT Generation - Parameter Validation")
    class ParameterValidationTests {

        @Test
        @DisplayName("Should throw exception when agentIdentity is null")
        void shouldThrowExceptionWhenAgentIdentityIsNull() {
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            assertThatThrownBy(() -> witGenerator.generateWit(null, wptPublicKeyJson, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Subject cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when wptPublicKey is null")
        void shouldThrowExceptionWhenWptPublicKeyIsNull() {
            long expirationSeconds = 3600;

            assertThatThrownBy(() -> witGenerator.generateWit(workloadId, null, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WPT public key cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when wptPublicKey is empty")
        void shouldThrowExceptionWhenWptPublicKeyIsEmpty() {
            long expirationSeconds = 3600;

            assertThatThrownBy(() -> witGenerator.generateWit(workloadId, "  ", expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WPT public key cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when wptPublicKey is invalid")
        void shouldThrowExceptionWhenWptPublicKeyIsInvalid() {
            long expirationSeconds = 3600;
            String invalidPublicKey = "invalid-jwk-format";

            assertThatThrownBy(() -> witGenerator.generateWit(workloadId, invalidPublicKey, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Invalid WPT public key format");
        }

        @Test
        @DisplayName("Should throw exception when expirationSeconds is zero")
        void shouldThrowExceptionWhenExpirationSecondsIsZero() {
            long expirationSeconds = 0;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            assertThatThrownBy(() -> witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }

        @Test
        @DisplayName("Should throw exception when expirationSeconds is negative")
        void shouldThrowExceptionWhenExpirationSecondsIsNegative() {
            long expirationSeconds = -100;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            assertThatThrownBy(() -> witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Expiration seconds must be positive");
        }
    }

    @Nested
    @DisplayName("WIT Generation - Constructor Validation")
    class ConstructorValidationTests {

        @Test
        @DisplayName("Should throw exception when signingKey is null")
        void shouldThrowExceptionWhenSigningKeyIsNull() {
            assertThatThrownBy(() -> new WitGenerator(null, trustDomain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Signing key cannot be null");
        }

        @Test
        @DisplayName("Should throw exception when trustDomain is null")
        void shouldThrowExceptionWhenTrustDomainIsNull() {
            assertThatThrownBy(() -> new WitGenerator(signingKey, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Trust domain cannot be null");
        }
    }

    @Nested
    @DisplayName("WIT Generation - Protocol Compliance")
    class ProtocolComplianceTests {

        @Test
        @DisplayName("Should use correct media type 'wit+jwt'")
        void shouldUseCorrectMediaType() throws JOSEException, ParseException {
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            assertThat(wit.header().type()).isEqualTo("wit+jwt");
        }

        @Test
        @DisplayName("Should include subject as Workload Identifier")
        void shouldIncludeSubjectAsWorkloadIdentifier() throws JOSEException, ParseException {
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            assertThat(wit.getSubject()).isEqualTo(workloadId);
            assertThat(wit.getWorkloadIdentifier()).isEqualTo(workloadId);
        }

        @Test
        @DisplayName("Should embed Ed25519 OKP key for WPT verification")
        void shouldEmbedEd25519KeyForWptVerification() throws JOSEException, ParseException {
            long expirationSeconds = 3600;
            String wptPublicKeyJson = wptPublicKey.toJSONString();

            WorkloadIdentityToken wit = witGenerator.generateWit(workloadId, wptPublicKeyJson, expirationSeconds);

            assertThat(wit.getConfirmation()).isNotNull();
            assertThat(wit.getConfirmation().jwk()).isNotNull();
            assertThat(wit.getConfirmation().jwk().x()).isNotBlank();
        }
    }
}
