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
package ai.shao.openagentauth.core.model.token;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WorkloadProofToken}.
 */
@DisplayName("WorkloadProofToken Tests")
class WorkloadProofTokenTest {

    private Date futureExpirationTime;
    private Date pastExpirationTime;
    private WorkloadProofToken.Claims validClaims;

    @BeforeEach
    void setUp() {
        futureExpirationTime = new Date(System.currentTimeMillis() + 3600000);
        pastExpirationTime = new Date(System.currentTimeMillis() - 3600000);

        validClaims = WorkloadProofToken.Claims.builder()
                .audience("https://resource-server.example.com")
                .expirationTime(futureExpirationTime)
                .jwtId("test-jti-456")
                .workloadTokenHash("abc123def456")
                .accessTokenHash("xyz789uvw012")
                .build();
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build token with all fields")
        void shouldBuildTokenWithAllFields() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .claims(validClaims)
                    .signature("test-signature")
                    .jwtString("test.jwt.string")
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.claims()).isEqualTo(validClaims);
            assertThat(token.signature()).isEqualTo("test-signature");
            assertThat(token.jwtString()).isEqualTo("test.jwt.string");
        }

        @Test
        @DisplayName("Should build token with minimal required fields")
        void shouldBuildTokenWithMinimalRequiredFields() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .claims(validClaims)
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.claims()).isEqualTo(validClaims);
            assertThat(token.signature()).isNull();
            assertThat(token.jwtString()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when building with null claims")
        void shouldThrowExceptionWhenBuildingWithNullClaims() {
            assertThatThrownBy(() -> WorkloadProofToken.builder()
                    .claims(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("claims is REQUIRED for WPT");
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should return true for expired token")
        void shouldReturnTrueForExpiredToken() {
            WorkloadProofToken.Claims expiredClaims = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(pastExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .claims(expiredClaims)
                    .build();

            assertThat(token.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should return true for valid token")
        void shouldReturnTrueForValidToken() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .claims(validClaims)
                    .build();

            assertThat(token.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should return true for valid token without expiration time")
        void shouldReturnTrueForValidTokenWithoutExpirationTime() {
            WorkloadProofToken.Claims claimsWithoutExpiration = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .claims(claimsWithoutExpiration)
                    .build();

            assertThat(token.isValid()).isTrue();
        }
    }

    @Nested
    @DisplayName("Claims Tests")
    class ClaimsTests {

        @Test
        @DisplayName("Should build claims with all fields")
        void shouldBuildClaimsWithAllFields() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience("https://resource-server.example.com")
                    .expirationTime(futureExpirationTime)
                    .jwtId("test-jti")
                    .workloadTokenHash("abc123")
                    .accessTokenHash("xyz789")
                    .build();

            assertThat(claims.audience()).isEqualTo("https://resource-server.example.com");
            assertThat(claims.expirationTime()).isEqualTo(futureExpirationTime);
            assertThat(claims.jwtId()).isEqualTo("test-jti");
            assertThat(claims.workloadTokenHash()).isEqualTo("abc123");
            assertThat(claims.accessTokenHash()).isEqualTo("xyz789");
        }

        @Test
        @DisplayName("Should build claims with minimal required fields")
        void shouldBuildClaimsWithMinimalRequiredFields() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(claims.audience()).isNull();
            assertThat(claims.expirationTime()).isNull();
            assertThat(claims.jwtId()).isNull();
            assertThat(claims.workloadTokenHash()).isEqualTo("abc123");
            assertThat(claims.accessTokenHash()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when building claims with null workload token hash")
        void shouldThrowExceptionWhenBuildingClaimsWithNullWorkloadTokenHash() {
            assertThatThrownBy(() -> WorkloadProofToken.Claims.builder()
                    .workloadTokenHash(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("workloadTokenHash (wth) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when building claims with empty workload token hash")
        void shouldThrowExceptionWhenBuildingClaimsWithEmptyWorkloadTokenHash() {
            assertThatThrownBy(() -> WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("workloadTokenHash (wth) is REQUIRED");
        }

        @Test
        @DisplayName("Should check if claims are expired")
        void shouldCheckIfClaimsAreExpired() {
            WorkloadProofToken.Claims expiredClaims = WorkloadProofToken.Claims.builder()
                    .expirationTime(pastExpirationTime)
                    .workloadTokenHash("abc123")
                    .build();

            assertThat(expiredClaims.isExpired()).isTrue();
        }
    }

    @Nested
    @DisplayName("Token Hash Tests")
    class TokenHashTests {

        @Test
        @DisplayName("Should handle workload token hash")
        void shouldHandleWorkloadTokenHash() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("wit-hash-123")
                    .build();

            assertThat(claims.workloadTokenHash()).isEqualTo("wit-hash-123");
        }

        @Test
        @DisplayName("Should handle access token hash")
        void shouldHandleAccessTokenHash() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .workloadTokenHash("wit-hash")
                    .accessTokenHash("at-hash-456")
                    .build();

            assertThat(claims.accessTokenHash()).isEqualTo("at-hash-456");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty audience")
        void shouldHandleEmptyAudience() {
            WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                    .audience("")
                    .workloadTokenHash("abc123")
                    .build();

            WorkloadProofToken token = WorkloadProofToken.builder()
                    .claims(claims)
                    .build();

            assertThat(token.getAudience()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty signature")
        void shouldHandleEmptySignature() {
            WorkloadProofToken token = WorkloadProofToken.builder()
                    .claims(validClaims)
                    .signature("")
                    .build();

            assertThat(token.signature()).isEqualTo("");
        }
    }
}
