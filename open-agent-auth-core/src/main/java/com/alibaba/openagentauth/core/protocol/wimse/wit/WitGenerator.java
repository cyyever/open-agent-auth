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
import com.alibaba.openagentauth.core.token.common.JwkConverter;
import com.alibaba.openagentauth.core.trust.model.TrustDomain;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Generator for Workload Identity Tokens (WIT). Signs WITs with Ed25519 ({@code alg=EdDSA}).
 */
public class WitGenerator {

    private static final Logger logger = LoggerFactory.getLogger(WitGenerator.class);

    private final OctetKeyPair signingKey;
    private final TrustDomain trustDomain;

    /**
     * Creates a new WIT generator. The signing key MUST be Ed25519 ({@link OctetKeyPair}).
     */
    public WitGenerator(JWK signingKey, TrustDomain trustDomain) {

        ValidationUtils.validateNotNull(signingKey, "Signing key");
        ValidationUtils.validateNotNull(trustDomain, "Trust domain");

        if (!(signingKey instanceof OctetKeyPair okp)) {
            throw new IllegalArgumentException(
                    "Signing key must be Ed25519 (OctetKeyPair); got: " + signingKey.getClass().getSimpleName());
        }

        this.signingKey = okp;
        this.trustDomain = trustDomain;
    }

    public WorkloadIdentityToken generateWit(String subject, String wptPublicKey, long expirationSeconds) throws JOSEException {

        if (ValidationUtils.isNullOrEmpty(subject)) {
            throw new IllegalArgumentException("Subject cannot be null or empty");
        }
        if (ValidationUtils.isNullOrEmpty(wptPublicKey)) {
            throw new IllegalArgumentException("WPT public key cannot be null or empty");
        }
        if (expirationSeconds <= 0) {
            throw new IllegalArgumentException("Expiration seconds must be positive");
        }

        logger.debug("Generating WIT for subject: {}", subject);

        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(expirationSeconds);

        JWK wptJwk = parseEd25519Jwk(wptPublicKey);

        WorkloadIdentityToken wit = buildWitObject(subject, expiration, wptJwk);

        wit = signAndSerializeWit(wit);
        logger.debug("Successfully generated WIT with subject: {}", subject);

        return wit;
    }

    public String generateWitAsString(String subject, String wptPublicKey, long expirationSeconds) throws JOSEException {
        WorkloadIdentityToken wit = generateWit(subject, wptPublicKey, expirationSeconds);
        return wit.jwtString();
    }

    private WorkloadIdentityToken buildWitObject(String subject, Instant expiration, JWK wptJwk) {

        Jwk jwkModel = JwkConverter.convertMapToJwk(wptJwk.toJSONObject());

        WorkloadIdentityToken.Claims.Confirmation confirmation = WorkloadIdentityToken.Claims.Confirmation.builder()
                .jwk(jwkModel)
                .build();

        String jwtId = UUID.randomUUID().toString();
        WorkloadIdentityToken.Claims.ClaimsBuilder claimsBuilder = WorkloadIdentityToken.Claims.builder()
                .issuer(trustDomain.getDomainId())
                .subject(subject)
                .expirationTime(Date.from(expiration))
                .jwtId(jwtId)
                .confirmation(confirmation);

        WorkloadIdentityToken.Header header = WorkloadIdentityToken.Header.builder()
                .type("wit+jwt")
                .build();

        return WorkloadIdentityToken.builder()
                .header(header)
                .claims(claimsBuilder.build())
                .build();
    }

    private WorkloadIdentityToken signAndSerializeWit(WorkloadIdentityToken wit) throws JOSEException {
        try {
            JWSSigner signer = new Ed25519Signer(signingKey);
            String keyId = signingKey.getKeyID();

            String signedJwtString = WitSerializer.serialize(wit, signer, keyId);

            String[] parts = signedJwtString.split("\\.");
            String signature = parts.length > 2 ? parts[2] : "";

            return WorkloadIdentityToken.builder()
                    .header(wit.header())
                    .claims(wit.claims())
                    .signature(signature)
                    .jwtString(signedJwtString)
                    .build();

        } catch (Exception e) {
            logger.error("Failed to sign WIT: keyId={}", signingKey.getKeyID(), e);
            throw new JOSEException("Failed to sign WIT", e);
        }
    }

    private JWK parseEd25519Jwk(String wptPublicKey) {
        try {
            JWK jwk = JWK.parse(wptPublicKey);
            if (!(jwk instanceof OctetKeyPair)) {
                throw new IllegalArgumentException(
                        "WPT public key must be Ed25519 (OctetKeyPair); got: " + jwk.getClass().getSimpleName());
            }
            return jwk;
        } catch (ParseException e) {
            throw new IllegalArgumentException("Invalid WPT public key format", e);
        }
    }

    public TrustDomain getTrustDomain() {
        return trustDomain;
    }
}
