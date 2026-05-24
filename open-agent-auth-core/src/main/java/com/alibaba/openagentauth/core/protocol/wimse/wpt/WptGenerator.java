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

import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.model.token.WorkloadProofToken;
import com.alibaba.openagentauth.core.token.common.JwtHashUtil;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Generator for Workload Proof Tokens (WPT). Signs WPTs with Ed25519 ({@code alg=EdDSA}).
 */
public class WptGenerator {

    private static final Logger logger = LoggerFactory.getLogger(WptGenerator.class);


    public WptGenerator() {
    }

    public WorkloadProofToken generateWpt(
            WorkloadIdentityToken wit,
            JWK wptPrivateKey,
            long expirationSeconds
    ) throws JOSEException {

        ValidationUtils.validateNotNull(wit, "WIT");
        ValidationUtils.validateNotNull(wptPrivateKey, "WPT private key");
        if (expirationSeconds <= 0) {
            throw new IllegalArgumentException("Expiration seconds must be positive");
        }

        if (!(wptPrivateKey instanceof OctetKeyPair okp)) {
            throw new IllegalArgumentException(
                    "WPT private key must be Ed25519 (OctetKeyPair); got: "
                            + wptPrivateKey.getClass().getSimpleName());
        }

        Instant now = Instant.now();
        Instant expiration = now.plusSeconds(expirationSeconds);

        String witJwtString = wit.jwtString();
        if (ValidationUtils.isNullOrEmpty(witJwtString)) {
            throw new JOSEException("WIT missing JWT string, cannot compute wth");
        }
        String wth = JwtHashUtil.computeWitHash(witJwtString);

        WorkloadProofToken wpt = buildWptObject(wth, expiration);
        wpt = signAndSerializeWpt(wpt, okp);

        logger.debug("Successfully generated and signed WPT: {}", wpt.jwtString());
        return wpt;
    }

    public String generateWptAsString(WorkloadIdentityToken wit, JWK wptPrivateKey, long expirationSeconds) throws JOSEException {
        return generateWpt(wit, wptPrivateKey, expirationSeconds).jwtString();
    }

    private WorkloadProofToken buildWptObject(String wth, Instant expiration) {
        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .workloadTokenHash(wth)
                .expirationTime(Date.from(expiration))
                .jwtId(UUID.randomUUID().toString())
                .build();

        return WorkloadProofToken.builder()
                .claims(claims)
                .build();
    }

    private WorkloadProofToken signAndSerializeWpt(WorkloadProofToken wpt, OctetKeyPair signingKey) throws JOSEException {
        try {
            JWSSigner signer = new Ed25519Signer(signingKey);

            String signedJwtString = WptSerializer.serialize(wpt, signer);

            String[] parts = signedJwtString.split("\\.");
            String signature = parts.length > 2 ? parts[2] : "";

            return WorkloadProofToken.builder()
                    .claims(wpt.claims())
                    .signature(signature)
                    .jwtString(signedJwtString)
                    .build();

        } catch (Exception e) {
            logger.error("Failed to sign WPT", e);
            throw new JOSEException("Failed to sign WPT", e);
        }
    }
}
