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
package com.alibaba.openagentauth.core.model.token;

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link WorkloadIdentityToken}.
 */
@DisplayName("WorkloadIdentityToken Tests")
class WorkloadIdentityTokenTest {

    private Date futureExpirationTime;
    private Date pastExpirationTime;
    private Jwk testJwk;
    private WorkloadIdentityToken.Header validHeader;
    private WorkloadIdentityToken.Claims validClaims;

    @BeforeEach
    void setUp() {
        futureExpirationTime = new Date(System.currentTimeMillis() + 3600000);
        pastExpirationTime = new Date(System.currentTimeMillis() - 3600000);

        testJwk = Jwk.builder()
                .keyType(Jwk.KeyType.OKP)
                .curve(Jwk.Curve.Ed25519)
                .x("test_x_value")
                .build();

        validHeader = WorkloadIdentityToken.Header.builder()
                .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                .build();

        WorkloadIdentityToken.Claims.Confirmation confirmation = WorkloadIdentityToken.Claims.Confirmation.builder()
                .jwk(testJwk)
                .build();

        validClaims = WorkloadIdentityToken.Claims.builder()
                .issuer("https://idp.example.com")
                .subject("spiffe://example.com/workload/my-workload")
                .expirationTime(futureExpirationTime)
                .jwtId("test-jti-123")
                .confirmation(confirmation)
                .build();
    }

    @Nested
    @DisplayName("Builder Tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build token with all fields")
        void shouldBuildTokenWithAllFields() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("test-signature")
                    .jwtString("test.jwt.string")
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.header()).isEqualTo(validHeader);
            assertThat(token.claims()).isEqualTo(validClaims);
            assertThat(token.signature()).isEqualTo("test-signature");
            assertThat(token.jwtString()).isEqualTo("test.jwt.string");
        }

        @Test
        @DisplayName("Should build token with minimal required fields")
        void shouldBuildTokenWithMinimalRequiredFields() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token).isNotNull();
            assertThat(token.header()).isEqualTo(validHeader);
            assertThat(token.claims()).isEqualTo(validClaims);
            assertThat(token.signature()).isNull();
            assertThat(token.jwtString()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when building with null header")
        void shouldThrowExceptionWhenBuildingWithNullHeader() {
            assertThatThrownBy(() -> WorkloadIdentityToken.builder()
                    .header(null)
                    .claims(validClaims)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("header is REQUIRED for WIT");
        }

        @Test
        @DisplayName("Should throw exception when building with null claims")
        void shouldThrowExceptionWhenBuildingWithNullClaims() {
            assertThatThrownBy(() -> WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("claims is REQUIRED for WIT");
        }
    }

    @Nested
    @DisplayName("Validation Tests")
    class ValidationTests {

        @Test
        @DisplayName("Should return true for expired token")
        void shouldReturnTrueForExpiredToken() {
            WorkloadIdentityToken.Claims expiredClaims = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/expired")
                    .expirationTime(pastExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(expiredClaims)
                    .build();

            assertThat(token.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should return true for valid token")
        void shouldReturnTrueForValidToken() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.isValid()).isTrue();
        }

        @Test
        @DisplayName("Should return false for expired token in isValid")
        void shouldReturnFalseForExpiredTokenInIsValid() {
            WorkloadIdentityToken.Claims expiredClaims = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/expired")
                    .expirationTime(pastExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(expiredClaims)
                    .build();

            assertThat(token.isValid()).isFalse();
        }

        @Test
        @DisplayName("Should return false when not expired")
        void shouldReturnFalseWhenNotExpired() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .build();

            assertThat(token.isExpired()).isFalse();
        }
    }

    @Nested
    @DisplayName("Header Tests")
    class HeaderTests {

        @Test
        @DisplayName("Should build header with type")
        void shouldBuildHeaderWithType() {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .build();

            assertThat(header.type()).isEqualTo(WorkloadIdentityToken.Header.MEDIA_TYPE);
        }

        @Test
        @DisplayName("Should build header with default type")
        void shouldBuildHeaderWithDefaultType() {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder().build();

            assertThat(header.type()).isEqualTo(WorkloadIdentityToken.Header.MEDIA_TYPE);
        }

        @Test
        @DisplayName("Should throw exception when building header with null type")
        void shouldThrowExceptionWhenBuildingHeaderWithNullType() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Header.builder()
                    .type(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("type (typ) is REQUIRED and should be 'wit+jwt'");
        }

        @Test
        @DisplayName("Should throw exception when building header with empty type")
        void shouldThrowExceptionWhenBuildingHeaderWithEmptyType() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Header.builder()
                    .type("")
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("type (typ) is REQUIRED and should be 'wit+jwt'");
        }

        @Test
        @DisplayName("Should implement equals correctly for header")
        void shouldImplementEqualsCorrectlyForHeader() {
            WorkloadIdentityToken.Header header1 = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .build();

            WorkloadIdentityToken.Header header2 = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .build();

            assertThat(header1).isEqualTo(header2);
            assertThat(header1).isNotEqualTo(null);
            assertThat(header1).isNotEqualTo("string");
        }

        @Test
        @DisplayName("Should implement hashCode correctly for header")
        void shouldImplementHashCodeCorrectlyForHeader() {
            WorkloadIdentityToken.Header header1 = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .build();

            WorkloadIdentityToken.Header header2 = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .build();

            assertThat(header1.hashCode()).isEqualTo(header2.hashCode());
        }

        @Test
        @DisplayName("Should implement toString for header")
        void shouldImplementToStringForHeader() {
            WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                    .type(WorkloadIdentityToken.Header.MEDIA_TYPE)
                    .build();

            String toString = header.toString();
            assertThat(toString).contains("wit+jwt");
        }
    }

    @Nested
    @DisplayName("Claims Tests")
    class ClaimsTests {

        @Test
        @DisplayName("Should build claims with all fields")
        void shouldBuildClaimsWithAllFields() {
            WorkloadIdentityToken.Claims.Confirmation confirmation = WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(testJwk)
                    .build();

            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .issuer("https://idp.example.com")
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .jwtId("test-jti")
                    .confirmation(confirmation)
                    .build();

            assertThat(claims.issuer()).isEqualTo("https://idp.example.com");
            assertThat(claims.subject()).isEqualTo("spiffe://example.com/workload/test");
            assertThat(claims.expirationTime()).isEqualTo(futureExpirationTime);
            assertThat(claims.jwtId()).isEqualTo("test-jti");
            assertThat(claims.confirmation()).isEqualTo(confirmation);
            assertThat(claims.jwk()).isEqualTo(testJwk);
        }

        @Test
        @DisplayName("Should build claims with minimal required fields")
        void shouldBuildClaimsWithMinimalRequiredFields() {
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(futureExpirationTime)
                    .build();

            assertThat(claims.issuer()).isNull();
            assertThat(claims.subject()).isEqualTo("spiffe://example.com/workload/test");
            assertThat(claims.expirationTime()).isEqualTo(futureExpirationTime);
            assertThat(claims.jwtId()).isNull();
            assertThat(claims.confirmation()).isNull();
        }

        @Test
        @DisplayName("Should throw exception when building claims with null subject")
        void shouldThrowExceptionWhenBuildingClaimsWithNullSubject() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Claims.builder()
                    .subject(null)
                    .expirationTime(futureExpirationTime)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("subject (sub) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when building claims with empty subject")
        void shouldThrowExceptionWhenBuildingClaimsWithEmptySubject() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Claims.builder()
                    .subject("")
                    .expirationTime(futureExpirationTime)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("subject (sub) is REQUIRED");
        }

        @Test
        @DisplayName("Should throw exception when building claims with null expiration time")
        void shouldThrowExceptionWhenBuildingClaimsWithNullExpirationTime() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Claims.builder()
                    .subject("spiffe://example.com/workload/test")
                    .expirationTime(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("expirationTime (exp) is REQUIRED");
        }

        @Test
        @DisplayName("Should check if claims are expired")
        void shouldCheckIfClaimsAreExpired() {
            WorkloadIdentityToken.Claims expiredClaims = WorkloadIdentityToken.Claims.builder()
                    .subject("spiffe://example.com/workload/expired")
                    .expirationTime(pastExpirationTime)
                    .build();

            assertThat(expiredClaims.isExpired()).isTrue();
        }

        @Test
        @DisplayName("Should return workload identifier")
        void shouldReturnWorkloadIdentifier() {
            assertThat(validClaims.getWorkloadIdentifier()).isEqualTo("spiffe://example.com/workload/my-workload");
        }
    }

    @Nested
    @DisplayName("Confirmation Tests")
    class ConfirmationTests {

        @Test
        @DisplayName("Should build confirmation with JWK")
        void shouldBuildConfirmationWithJwk() {
            WorkloadIdentityToken.Claims.Confirmation confirmation = WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(testJwk)
                    .build();

            assertThat(confirmation.jwk()).isEqualTo(testJwk);
        }

        @Test
        @DisplayName("Should throw exception when building confirmation with null JWK")
        void shouldThrowExceptionWhenBuildingConfirmationWithNullJwk() {
            assertThatThrownBy(() -> WorkloadIdentityToken.Claims.Confirmation.builder()
                    .jwk(null)
                    .build())
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("jwk is REQUIRED in confirmation (cnf) claim");
        }
    }

    @Nested
    @DisplayName("Edge Cases Tests")
    class EdgeCasesTests {

        @Test
        @DisplayName("Should handle empty signature")
        void shouldHandleEmptySignature() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .signature("")
                    .build();

            assertThat(token.signature()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle empty jwtString")
        void shouldHandleEmptyJwtString() {
            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(validClaims)
                    .jwtString("")
                    .build();

            assertThat(token.jwtString()).isEqualTo("");
        }

        @Test
        @DisplayName("Should handle SPIFFE format subject")
        void shouldHandleSpiffeFormatSubject() {
            WorkloadIdentityToken.Claims claims = WorkloadIdentityToken.Claims.builder()
                    .subject("spiffe://example.com/ns/default/sa/my-service")
                    .expirationTime(futureExpirationTime)
                    .build();

            WorkloadIdentityToken token = WorkloadIdentityToken.builder()
                    .header(validHeader)
                    .claims(claims)
                    .build();

            assertThat(token.getSubject()).isEqualTo("spiffe://example.com/ns/default/sa/my-service");
        }
    }
}
