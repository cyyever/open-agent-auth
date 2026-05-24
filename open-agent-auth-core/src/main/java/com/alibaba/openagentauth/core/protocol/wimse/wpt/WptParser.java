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
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Set;

/**
 * Parser for Workload Proof Tokens (WPT). Converts signed JWT strings into
 * structured {@link WorkloadProofToken} objects.
 */
public class WptParser {

    private static final String EXPECTED_TYP = "wpt+jwt";

    /** Per AAP spec §3: DPoP allows {alg, typ, jwk} JOSE header params. */
    private static final Set<String> ALLOWED_HEADER_PARAMS = Set.of("alg", "typ", "jwk");

    private static final Logger logger = LoggerFactory.getLogger(WptParser.class);

    /**
     * Parses a WPT from a signed JWT string.
     * <p>
     * This method extracts all claims from the JWT and constructs a structured
     * {@link WorkloadProofToken} object. It validates the input and provides
     * detailed error messages if parsing fails.
     * </p>
     *
     * @param wptJwt the JWT string representing the WPT
     * @return a WorkloadProofToken object
     * @throws ParseException if parsing fails due to invalid JWT structure or claims
     * @throws IllegalArgumentException if wptJwt is null or empty
     */
    public WorkloadProofToken parse(String wptJwt) throws ParseException {

        // Validate input
        if (ValidationUtils.isNullOrEmpty(wptJwt)) {
            throw new IllegalArgumentException("WPT JWT string cannot be null or empty");
        }

        logger.debug("Parsing Workload Proof Token");

        // Parse signed JWT
        SignedJWT signedJwt = SignedJWT.parse(wptJwt);

        // Extract JWT claims
        JWTClaimsSet claimsSet = signedJwt.getJWTClaimsSet();

        // Build structured WPT object
        WorkloadProofToken wpt = buildWorkloadProofToken(signedJwt, claimsSet, wptJwt);

        logger.debug("Successfully parsed WPT with JWT ID: {}", wpt.getJwtId());
        return wpt;
    }

    /**
     * Builds a structured WorkloadProofToken object from parsed components.
     *
     * @param signedJwt the signed JWT
     * @param claimsSet the JWT claims set
     * @param jwtString the original JWT string
     * @return a WorkloadProofToken object
     * @throws ParseException if claims parsing fails
     */
    private WorkloadProofToken buildWorkloadProofToken(
            SignedJWT signedJwt,
            JWTClaimsSet claimsSet,
            String jwtString
    ) throws ParseException {

        JWSAlgorithm alg = signedJwt.getHeader().getAlgorithm();
        if (!JWSAlgorithm.EdDSA.equals(alg)) {
            throw new ParseException(
                    "WPT alg header must be 'EdDSA', got: " + alg, 0);
        }

        JOSEObjectType typ = signedJwt.getHeader().getType();
        if (typ == null || !EXPECTED_TYP.equals(typ.getType())) {
            throw new ParseException(
                    "WPT typ header must be '" + EXPECTED_TYP + "', got: " + typ, 0);
        }

        Set<String> headerParams = signedJwt.getHeader().toJSONObject().keySet();
        for (String name : headerParams) {
            if (!ALLOWED_HEADER_PARAMS.contains(name)) {
                throw new ParseException(
                        "WPT JOSE header contains disallowed parameter: " + name, 0);
            }
        }

        WorkloadProofToken.Header header = WorkloadProofToken.Header.builder()
                .type(typ.getType())
                .build();

        // Build claims
        WorkloadProofToken.Claims claims = WorkloadProofToken.Claims.builder()
                .audience(getStringClaim(claimsSet, "aud"))
                .expirationTime(claimsSet.getExpirationTime())
                .jwtId(claimsSet.getJWTID())
                .workloadTokenHash(getStringClaim(claimsSet, "wth"))
                .accessTokenHash(getStringClaim(claimsSet, "ath"))
                .build();

        // Build WPT
        return WorkloadProofToken.builder()
                .header(header)
                .claims(claims)
                .signature(signedJwt.getSignature().toString())
                .jwtString(jwtString)
                .build();
    }

    /**
     * Gets a string claim from the claims set.
     *
     * @param claimsSet the JWT claims set
     * @param claimName the claim name
     * @return the claim value, or null if not present
     */
    private String getStringClaim(JWTClaimsSet claimsSet, String claimName) throws ParseException {
        Object value = claimsSet.getClaim(claimName);
        if (value == null) {
            return null;
        }
        return value.toString();
    }

}