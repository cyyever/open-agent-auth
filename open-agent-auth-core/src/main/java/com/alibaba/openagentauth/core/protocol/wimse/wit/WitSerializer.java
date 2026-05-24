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

import com.alibaba.openagentauth.core.model.token.WorkloadIdentityToken;
import com.alibaba.openagentauth.core.token.common.JwkConverter;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jwt.JWTClaimsSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

/**
 * Serializer for Workload Identity Tokens (WIT). Converts structured
 * {@link WorkloadIdentityToken} objects into signed JWT strings.
 */
public class WitSerializer {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(WitSerializer.class);

    /**
     * Serializes and signs a WorkloadIdentityToken object to a JWT string.
     * Per AAP spec §3 the JWS header carries only {alg, typ}; the
     * verification key is resolved out-of-band by issuer/subject, so no
     * {@code kid} is emitted.
     *
     * @param wit the WorkloadIdentityToken object to serialize and sign
     * @param signer the JWSSigner to use for signing
     * @return the signed JWT string representation
     * @throws JOSEException if serialization or signing fails
     */
    public static String serialize(WorkloadIdentityToken wit, JWSSigner signer) throws JOSEException {

        ValidationUtils.validateNotNull(wit, "WorkloadIdentityToken");
        ValidationUtils.validateNotNull(signer, "JWSSigner");

        try {
            // Build JWSObject from the structured WIT
            JWSObject jwsObject = buildJWSObject(wit);

            // Sign the JWSObject
            jwsObject.sign(signer);

            // Serialize and return the signed JWT string
            return jwsObject.serialize();

        } catch (Exception e) {
            logger.error("Failed to serialize and sign WorkloadIdentityToken to JWT string", e);
            throw new JOSEException("Failed to serialize and sign WorkloadIdentityToken to JWT string", e);
        }
    }

    private static JWSObject buildJWSObject(WorkloadIdentityToken wit) throws JOSEException {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                    .type(new JOSEObjectType(WorkloadIdentityToken.MEDIA_TYPE))
                    .build();

            // Build JWTClaimsSet from WIT claims
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                    .issuer(wit.getIssuer())
                    .subject(wit.getSubject())
                    .expirationTime(wit.getExpirationTime())
                    .jwtID(wit.getJwtId());

            // Add confirmation claim (cnf) if present
            if (wit.getConfirmation() != null) {
                Map<String, Object> cnfMap = new java.util.HashMap<>();
                Map<String, Object> jwkMap = JwkConverter.convertJwkToMap(wit.getConfirmation().jwk());
                cnfMap.put("jwk", jwkMap);
                claimsBuilder.claim("cnf", cnfMap);
            }

            JWTClaimsSet claimsSet = claimsBuilder.build();

            // Create JWSObject with header and payload
            JWSObject jwsObject = new JWSObject(header, new Payload(claimsSet.toJSONObject()));
            logger.debug("Built JWSObject ready for signing");
            return jwsObject;

        } catch (Exception e) {
            logger.error("Failed to build JWSObject from WIT", e);
            throw new JOSEException("Failed to build JWSObject from WIT", e);
        }
    }

}