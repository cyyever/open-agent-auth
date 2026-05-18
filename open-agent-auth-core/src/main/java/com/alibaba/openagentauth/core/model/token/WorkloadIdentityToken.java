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
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Date;
import java.util.Objects;

/**
 * Represents a Workload Identity Token (WIT). A WIT is a JWT that identifies a workload
 * and contains a public key in the {@code cnf} claim used to verify the corresponding
 * Workload Proof Token (WPT).
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519 - JSON Web Token (JWT)</a>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WorkloadIdentityToken {

    /**
     * The JOSE header of the WIT.
     */
    private final Header header;

    /**
     * The claims (payload) of the WIT.
     */
    private final Claims claims;

    /**
     * The signature of the WIT.
     * <p>
     * This field stores the base64url-encoded signature of the JWT.
     * It is populated after signing the token.
     * </p>
     */
    @JsonProperty("signature")
    private final String signature;

    /**
     * The JWT string representation of the signed WIT.
     * <p>
     * This field stores the complete JWT string (header.payload.signature)
     * after the token has been signed. It is populated after signing the token.
     * </p>
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private final String jwtString;

    private WorkloadIdentityToken(Builder builder) {
        this.header = builder.header;
        this.claims = builder.claims;
        this.signature = builder.signature;
        this.jwtString = builder.jwtString;
    }

    /**
     * Gets the JOSE header of the WIT.
     *
     * @return the header
     */
    public Header getHeader() {
        return header;
    }

    /**
     * Gets the claims (payload) of the WIT.
     *
     * @return the claims
     */
    public Claims getClaims() {
        return claims;
    }

    /**
     * Gets the signature of the WIT.
     *
     * @return the base64url-encoded signature, or null if not signed
     */
    public String getSignature() {
        return signature;
    }

    /**
     * Gets the JWT string representation of the signed WIT.
     *
     * @return the complete JWT string (header.payload.signature), or null if not signed
     */
    public String getJwtString() {
        return jwtString;
    }

    /**
     * Gets the issuer (iss) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getIssuer()}.
     * </p>
     *
     * @return the issuer, or null if not present
     */
    public String getIssuer() {
        return claims != null ? claims.getIssuer() : null;
    }

    /**
     * Gets the subject (sub) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getSubject()}.
     * </p>
     *
     * @return the subject (Workload Identifier)
     */
    public String getSubject() {
        return claims != null ? claims.getSubject() : null;
    }

    /**
     * Gets the expiration time (exp) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getExpirationTime()}.
     * </p>
     *
     * @return the expiration time
     */
    public Date getExpirationTime() {
        return claims != null ? claims.getExpirationTime() : null;
    }

    /**
     * Gets the JWT ID (jti) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getJwtId()}.
     * </p>
     *
     * @return the JWT ID, or null if not present
     */
    public String getJwtId() {
        return claims != null ? claims.getJwtId() : null;
    }

    /**
     * Gets the Workload Identifier from the subject claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getWorkloadIdentifier()}.
     * </p>
     *
     * @return the Workload Identifier
     */
    public String getWorkloadIdentifier() {
        return claims != null ? claims.getWorkloadIdentifier() : null;
    }

    /**
     * Gets the confirmation (cnf) claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getConfirmation()}.
     * </p>
     *
     * @return the confirmation claim
     */
    public Claims.Confirmation getConfirmation() {
        return claims != null ? claims.getConfirmation() : null;
    }

    /**
     * Gets the JWK from the confirmation claim.
     * <p>
     * Convenience method that delegates to {@link Claims#getJwk()}.
     * </p>
     *
     * @return the JWK, or null if not present
     */
    public Jwk getJwk() {
        return claims != null ? claims.getJwk() : null;
    }

    /**
     * Checks if the token is expired.
     *
     * @return true if the token is expired, false otherwise
     */
    public boolean isExpired() {
        return claims != null && claims.isExpired();
    }

    /**
     * Checks if the WIT is currently valid (not before current time and not expired).
     *
     * @return true if the WIT is valid, false otherwise
     */
    public boolean isValid() {
        return claims != null && claims.isValid();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        WorkloadIdentityToken that = (WorkloadIdentityToken) o;
        return Objects.equals(header, that.header) &&
               Objects.equals(claims, that.claims) &&
               Objects.equals(signature, that.signature);
    }

    @Override
    public int hashCode() {
        return Objects.hash(header, claims, signature);
    }

    @Override
    public String toString() {
        return "WorkloadIdentityToken{" +
                "header=" + header +
                ", claims=" + claims +
                ", signature='" + signature + '\'' +
                '}';
    }

    /**
     * Creates a new builder for {@link WorkloadIdentityToken}.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link WorkloadIdentityToken}.
     */
    public static class Builder {
        private Header header;
        private Claims claims;
        private String signature;
        private String jwtString;

        /**
         * Sets the JOSE header.
         *
         * @param header the header
         * @return this builder instance
         */
        public Builder header(Header header) {
            this.header = header;
            return this;
        }

        /**
         * Sets the claims (payload).
         *
         * @param claims the claims
         * @return this builder instance
         */
        public Builder claims(Claims claims) {
            this.claims = claims;
            return this;
        }

        /**
         * Sets the signature.
         *
         * @param signature the base64url-encoded signature
         * @return this builder instance
         */
        public Builder signature(String signature) {
            this.signature = signature;
            return this;
        }

        /**
         * Sets the JWT string.
         *
         * @param jwtString the complete JWT string (header.payload.signature)
         * @return this builder instance
         */
        public Builder jwtString(String jwtString) {
            this.jwtString = jwtString;
            return this;
        }

        /**
         * Builds the {@link WorkloadIdentityToken}.
         * <p>
         * Validates that the required header and claims are present.
         * </p>
         *
         * @return the built token
         * @throws IllegalStateException if the required header or claims are not set
         */
        public WorkloadIdentityToken build() {
            if (header == null) {
                throw new IllegalStateException("header is REQUIRED for WIT");
            }
            if (claims == null) {
                throw new IllegalStateException("claims is REQUIRED for WIT");
            }
            return new WorkloadIdentityToken(this);
        }
    }

    /**
     * JOSE Header for Workload Identity Token (WIT).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Header {

        /**
         * The media type for WIT.
         */
        public static final String MEDIA_TYPE = "wit+jwt";

        /**
         * Type parameter (typ).
         * <p>
         * The typ JOSE header parameter of the WIT conveys a media type of {@code wit+jwt}.
         * This is used to declare the media type of the complete JWT.
         * </p>
         */
        @JsonProperty("typ")
        private final String type;

        /**
         * Algorithm parameter (alg).
         * <p>
         * An identifier for an appropriate JWS asymmetric digital signature algorithm.
         * The algorithm MUST be an asymmetric signature algorithm.
         * </p>
         *
         * @see <a href="https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms">IANA JOSE Algorithms</a>
         */
        @JsonProperty("alg")
        private final String algorithm;

        private Header(HeaderBuilder builder) {
            this.type = builder.type;
            this.algorithm = builder.algorithm;
        }

        /**
         * Gets the type (typ) parameter.
         *
         * @return the type, should be {@code wit+jwt}
         */
        public String getType() {
            return type;
        }

        /**
         * Gets the algorithm (alg) parameter.
         *
         * @return the algorithm identifier
         */
        public String getAlgorithm() {
            return algorithm;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Header header = (Header) o;
            return Objects.equals(type, header.type) &&
                   Objects.equals(algorithm, header.algorithm);
        }

        @Override
        public int hashCode() {
            return Objects.hash(type, algorithm);
        }

        @Override
        public String toString() {
            return "Header{" +
                    "type='" + type + '\'' +
                    ", algorithm='" + algorithm + '\'' +
                    '}';
        }

        /**
         * Creates a new builder for {@link Header}.
         *
         * @return a new builder instance
         */
        public static HeaderBuilder builder() {
            return new HeaderBuilder();
        }

        /**
         * Builder for {@link Header}.
         */
        public static class HeaderBuilder {
            private String type = MEDIA_TYPE;
            private String algorithm;

            /**
             * Sets the type (typ) parameter.
             * <p>
             * Default value is {@code wit+jwt}.
             * </p>
             *
             * @param type the type
             * @return this builder instance
             */
            public HeaderBuilder type(String type) {
                this.type = type;
                return this;
            }

            /**
             * Sets the algorithm (alg) parameter.
             * <p>
             * The algorithm MUST be an asymmetric signature algorithm.
             * </p>
             *
             * @param algorithm the algorithm identifier (e.g., "ES256", "RS256")
             * @return this builder instance
             */
            public HeaderBuilder algorithm(String algorithm) {
                this.algorithm = algorithm;
                return this;
            }

            /**
             * Builds the {@link Header}.
             *
             * @return the built header
             * @throws IllegalStateException if required parameters are not set
             */
            public Header build() {
                if (ValidationUtils.isNullOrEmpty(type)) {
                    throw new IllegalStateException("type (typ) is REQUIRED and should be 'wit+jwt'");
                }
                if (ValidationUtils.isNullOrEmpty(algorithm)) {
                    throw new IllegalStateException("algorithm (alg) is REQUIRED");
                }
                return new Header(this);
            }
        }
    }

    /**
     * Claims (Payload) for Workload Identity Token (WIT).
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Claims {

        /**
         * Issuer claim (iss): principal that issued the WIT.
         */
        @JsonProperty("iss")
        private final String issuer;

        /**
         * Subject claim (sub): the Workload Identifier.
         */
        @JsonProperty("sub")
        private final String subject;

        /**
         * Expiration Time claim (exp): time after which the WIT must not be accepted.
         */
        @JsonProperty("exp")
        private final Date expirationTime;

        /**
         * JWT ID claim (jti): unique identifier for the WIT.
         */
        @JsonProperty("jti")
        private final String jwtId;

        /**
         * Confirmation claim (cnf): contains the public key used to verify the WPT.
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7800">RFC 7800 - Proof-of-Possession Key Semantics</a>
         */
        @JsonProperty("cnf")
        private final Confirmation confirmation;

        private Claims(ClaimsBuilder builder) {
            this.issuer = builder.issuer;
            this.subject = builder.subject;
            this.expirationTime = builder.expirationTime;
            this.jwtId = builder.jwtId;
            this.confirmation = builder.confirmation;
        }

        /**
         * Gets the issuer (iss) claim.
         *
         * @return the issuer, or null if not present
         */
        public String getIssuer() {
            return issuer;
        }

        /**
         * Gets the subject (sub) claim.
         *
         * @return the subject (Workload Identifier)
         */
        public String getSubject() {
            return subject;
        }

        /**
         * Gets the expiration time (exp) claim.
         *
         * @return the expiration time
         */
        public Date getExpirationTime() {
            return expirationTime;
        }

        /**
         * Gets the JWT ID (jti) claim.
         *
         * @return the JWT ID, or null if not present
         */
        public String getJwtId() {
            return jwtId;
        }

        /**
         * Gets the Workload Identifier from the subject claim.
         *
         * @return the Workload Identifier
         */
        public String getWorkloadIdentifier() {
            return subject;
        }

        /**
         * Gets the confirmation (cnf) claim.
         *
         * @return the confirmation claim
         */
        public Confirmation getConfirmation() {
            return confirmation;
        }

        /**
         * Gets the JWK from the confirmation claim.
         * <p>
         * This is a convenience method to extract the JWK from the cnf claim.
         * </p>
         *
         * @return the JWK, or null if not present
         */
        public Jwk getJwk() {
            return confirmation != null ? confirmation.getJwk() : null;
        }

        /**
         * Checks if the claims indicate the token is expired.
         *
         * @return true if expired, false otherwise
         */
        public boolean isExpired() {
            if (expirationTime == null) {
                return false;
            }
            return expirationTime.before(Date.from(Instant.now()));
        }

        /**
         * Checks if the claims indicate the token is currently valid (not expired).
         *
         * @return true if valid, false otherwise
         */
        public boolean isValid() {
            Date now = Date.from(Instant.now());
            return expirationTime == null || !now.after(expirationTime);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            Claims claims = (Claims) o;
            return Objects.equals(issuer, claims.issuer) &&
                   Objects.equals(subject, claims.subject) &&
                   Objects.equals(expirationTime, claims.expirationTime) &&
                   Objects.equals(jwtId, claims.jwtId) &&
                   Objects.equals(confirmation, claims.confirmation);
        }

        @Override
        public int hashCode() {
            return Objects.hash(issuer, subject, expirationTime, jwtId, confirmation);
        }

        @Override
        public String toString() {
            return "Claims{" +
                    "issuer='" + issuer + '\'' +
                    ", subject='" + subject + '\'' +
                    ", expirationTime=" + expirationTime +
                    ", jwtId='" + jwtId + '\'' +
                    ", confirmation=" + confirmation +
                    '}';
        }

        /**
         * Creates a new builder for {@link Claims}.
         *
         * @return a new builder instance
         */
        public static ClaimsBuilder builder() {
            return new ClaimsBuilder();
        }

        /**
         * Builder for {@link Claims}.
         */
        public static class ClaimsBuilder {
            private String issuer;
            private String subject;
            private Date expirationTime;
            private String jwtId;
            private Confirmation confirmation;

            /**
             * Sets the issuer (iss) claim.
             * <p>
             * This claim is OPTIONAL but RECOMMENDED.
             * </p>
             *
             * @param issuer the issuer
             * @return this builder instance
             */
            public ClaimsBuilder issuer(String issuer) {
                this.issuer = issuer;
                return this;
            }

            /**
             * Sets the subject (sub) claim.
             * <p>
             * This claim is REQUIRED. The value must be the Workload Identifier.
             * </p>
             *
             * @param subject the subject (Workload Identifier)
             * @return this builder instance
             */
            public ClaimsBuilder subject(String subject) {
                this.subject = subject;
                return this;
            }

            /**
             * Sets the expiration time (exp) claim.
             * <p>
             * This claim is REQUIRED.
             * </p>
             *
             * @param expirationTime the expiration time
             * @return this builder instance
             */
            public ClaimsBuilder expirationTime(Date expirationTime) {
                this.expirationTime = expirationTime;
                return this;
            }

            /**
             * Sets the JWT ID (jti) claim.
             *
             * @param jwtId the JWT ID
             * @return this builder instance
             */
            public ClaimsBuilder jwtId(String jwtId) {
                this.jwtId = jwtId;
                return this;
            }

            /**
             * Sets the confirmation (cnf) claim.
             * <p>
             * This claim is OPTIONAL but RECOMMENDED for WPT verification.
             * </p>
             *
             * @param confirmation the confirmation claim
             * @return this builder instance
             */
            public ClaimsBuilder confirmation(Confirmation confirmation) {
                this.confirmation = confirmation;
                return this;
            }

            /**
             * Builds the {@link Claims}. Required fields: {@code sub}, {@code exp}.
             *
             * @return the built claims
             * @throws IllegalStateException if required claims are not set
             */
            public Claims build() {
                if (ValidationUtils.isNullOrEmpty(subject)) {
                    throw new IllegalStateException("subject (sub) is REQUIRED");
                }
                if (expirationTime == null) {
                    throw new IllegalStateException("expirationTime (exp) is REQUIRED");
                }
                return new Claims(this);
            }
        }

        /**
         * Confirmation claim (cnf) structure as defined in RFC 7800.
         * <p>
         * The confirmation claim is used to prove possession of a key. In the context of WIT,
         * it contains the public key (JWK) that will be used to verify the Workload Proof Token (WPT).
         * </p>
         *
         * <h3>Structure</h3>
         * <pre>
         * {
         *   "cnf": {
         *     "jwk": {
         *       "kty": "EC",
         *       "crv": "P-256",
         *       "x": "...",
         *       "y": "..."
         *     }
         *   }
         * }
         * </pre>
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc7800">RFC 7800 - Proof-of-Possession Key Semantics</a>
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class Confirmation {

            /**
             * JSON Web Key (jwk): the public key represented as a JWK.
             */
            @JsonProperty("jwk")
            private final Jwk jwk;

            private Confirmation(ConfirmationBuilder builder) {
                this.jwk = builder.jwk;
            }

            /**
             * Gets the JSON Web Key (jwk).
             *
             * @return the JWK
             */
            public Jwk getJwk() {
                return jwk;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (o == null || getClass() != o.getClass()) return false;
                Confirmation that = (Confirmation) o;
                return Objects.equals(jwk, that.jwk);
            }

            @Override
            public int hashCode() {
                return Objects.hash(jwk);
            }

            @Override
            public String toString() {
                return "Confirmation{" +
                        "jwk=" + jwk +
                        '}';
            }

            /**
             * Creates a new builder for {@link Confirmation}.
             *
             * @return a new builder instance
             */
            public static ConfirmationBuilder builder() {
                return new ConfirmationBuilder();
            }

            /**
             * Builder for {@link Confirmation}.
             */
            public static class ConfirmationBuilder {
                private Jwk jwk;

                /**
                 * Sets the JSON Web Key (jwk).
                 * <p>
                 * This field is REQUIRED.
                 * </p>
                 *
                 * @param jwk the JWK
                 * @return this builder instance
                 */
                public ConfirmationBuilder jwk(Jwk jwk) {
                    this.jwk = jwk;
                    return this;
                }

                /**
                 * Builds the {@link Confirmation}.
                 * <p>
                 * Validates that the required jwk is present.
                 * </p>
                 *
                 * @return the built confirmation
                 * @throws IllegalStateException if jwk is not set
                 */
                public Confirmation build() {
                    if (jwk == null) {
                        throw new IllegalStateException("jwk is REQUIRED in confirmation (cnf) claim");
                    }
                    return new Confirmation(this);
                }
            }
        }
    }
}
