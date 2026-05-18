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

/**
 * Represents a Workload Identity Token (WIT). A WIT is a JWT that identifies a workload
 * and contains a public key in the {@code cnf} claim used to verify the corresponding
 * Workload Proof Token (WPT).
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record WorkloadIdentityToken(
        Header header,
        Claims claims,
        @JsonProperty("signature") String signature,
        @JsonProperty("jwtString") String jwtString) {

    public WorkloadIdentityToken {
        if (header == null) {
            throw new IllegalStateException("header is REQUIRED for WIT");
        }
        if (claims == null) {
            throw new IllegalStateException("claims is REQUIRED for WIT");
        }
    }

    public String getIssuer()                    { return claims != null ? claims.issuer()              : null; }
    public String getSubject()                   { return claims != null ? claims.subject()             : null; }
    public Date   getExpirationTime()            { return claims != null ? claims.expirationTime()      : null; }
    public String getJwtId()                     { return claims != null ? claims.jwtId()               : null; }
    public String getWorkloadIdentifier()        { return claims != null ? claims.subject()             : null; }
    public Claims.Confirmation getConfirmation() { return claims != null ? claims.confirmation()        : null; }
    public Jwk    getJwk()                       { return claims != null ? claims.jwk()                 : null; }

    public boolean isExpired() { return claims != null && claims.isExpired(); }
    public boolean isValid()   { return claims != null && claims.isValid();   }

    public static Builder builder() { return new Builder(); }

    public static class Builder {
        private Header header;
        private Claims claims;
        private String signature;
        private String jwtString;

        public Builder header(Header header)       { this.header = header;       return this; }
        public Builder claims(Claims claims)       { this.claims = claims;       return this; }
        public Builder signature(String signature) { this.signature = signature; return this; }
        public Builder jwtString(String jwtString) { this.jwtString = jwtString; return this; }

        public WorkloadIdentityToken build() {
            return new WorkloadIdentityToken(header, claims, signature, jwtString);
        }
    }

    /** JOSE Header for Workload Identity Token (WIT). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Header(
            @JsonProperty("typ") String type,
            @JsonProperty("alg") String algorithm) {

        public static final String MEDIA_TYPE = "wit+jwt";

        public Header {
            if (ValidationUtils.isNullOrEmpty(type)) {
                throw new IllegalStateException("type (typ) is REQUIRED and should be 'wit+jwt'");
            }
            if (ValidationUtils.isNullOrEmpty(algorithm)) {
                throw new IllegalStateException("algorithm (alg) is REQUIRED");
            }
        }

        public static HeaderBuilder builder() { return new HeaderBuilder(); }

        public static class HeaderBuilder {
            private String type = MEDIA_TYPE;
            private String algorithm;

            public HeaderBuilder type(String type)           { this.type = type;           return this; }
            public HeaderBuilder algorithm(String algorithm) { this.algorithm = algorithm; return this; }

            public Header build() {
                return new Header(type, algorithm);
            }
        }
    }

    /** Claims (Payload) for Workload Identity Token (WIT). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Claims(
            @JsonProperty("iss") String issuer,
            @JsonProperty("sub") String subject,
            @JsonProperty("exp") Date expirationTime,
            @JsonProperty("jti") String jwtId,
            @JsonProperty("cnf") Confirmation confirmation) {

        public Claims {
            if (ValidationUtils.isNullOrEmpty(subject)) {
                throw new IllegalStateException("subject (sub) is REQUIRED");
            }
            if (expirationTime == null) {
                throw new IllegalStateException("expirationTime (exp) is REQUIRED");
            }
        }

        /** Workload Identifier alias for subject. */
        public String getWorkloadIdentifier() { return subject; }

        /** JWK from the confirmation claim. */
        public Jwk jwk() { return confirmation != null ? confirmation.jwk() : null; }

        public boolean isExpired() {
            return expirationTime != null && expirationTime.before(Date.from(Instant.now()));
        }

        public boolean isValid() {
            return expirationTime == null || !Date.from(Instant.now()).after(expirationTime);
        }

        public static ClaimsBuilder builder() { return new ClaimsBuilder(); }

        public static class ClaimsBuilder {
            private String issuer;
            private String subject;
            private Date expirationTime;
            private String jwtId;
            private Confirmation confirmation;

            public ClaimsBuilder issuer(String issuer)               { this.issuer = issuer;                 return this; }
            public ClaimsBuilder subject(String subject)             { this.subject = subject;               return this; }
            public ClaimsBuilder expirationTime(Date expirationTime) { this.expirationTime = expirationTime; return this; }
            public ClaimsBuilder jwtId(String jwtId)                 { this.jwtId = jwtId;                   return this; }
            public ClaimsBuilder confirmation(Confirmation confirmation) { this.confirmation = confirmation; return this; }

            public Claims build() {
                return new Claims(issuer, subject, expirationTime, jwtId, confirmation);
            }
        }

        /**
         * Confirmation claim (cnf) structure as defined in RFC 7800.
         * Contains the JWK used to verify the corresponding WPT.
         */
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public record Confirmation(@JsonProperty("jwk") Jwk jwk) {

            public Confirmation {
                if (jwk == null) {
                    throw new IllegalStateException("jwk is REQUIRED in confirmation (cnf) claim");
                }
            }

            public static ConfirmationBuilder builder() { return new ConfirmationBuilder(); }

            public static class ConfirmationBuilder {
                private Jwk jwk;

                public ConfirmationBuilder jwk(Jwk jwk) { this.jwk = jwk; return this; }

                public Confirmation build() {
                    return new Confirmation(jwk);
                }
            }
        }
    }
}
