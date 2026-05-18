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
package com.alibaba.openagentauth.core.token.common;

import com.alibaba.openagentauth.core.util.ValidationUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Utility class for computing SHA-256 hashes of JWT strings, encoded as
 * {@code BASE64URL(SHA-256(ASCII(token_string)))}.
 */
public class JwtHashUtil {

    /**
     * Logger for this class.
     */
    private static final Logger logger = LoggerFactory.getLogger(JwtHashUtil.class);

    /**
     * Computes the SHA-256 hash of a JWT string.
     * <p>
     * The hash is computed using the following steps:
     * <ol>
     *   <li>Convert the JWT string to ASCII bytes</li>
     *   <li>Compute SHA-256 hash of the bytes</li>
     *   <li>Encode the hash using Base64URL encoding without padding</li>
     * </ol>
     * </p>
     *
     * @param jwtString the JWT string to hash
     * @return the base64url-encoded SHA-256 hash
     * @throws IllegalArgumentException if the JWT string is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available (should never happen)
     */
    public static String computeSha256Hash(String jwtString) {

        // Validate input
        if (ValidationUtils.isNullOrEmpty(jwtString)) {
            throw new IllegalArgumentException("JWT string cannot be null or empty");
        }

        try {
            // Get SHA-256 message digest
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            
            // Compute hash of the JWT string
            byte[] hash = digest.digest(jwtString.getBytes(StandardCharsets.UTF_8));
            
            // Encode using Base64URL without padding
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
            
        } catch (NoSuchAlgorithmException e) {
            // This should never happen as SHA-256 is required by Java specification
            logger.error("SHA-256 algorithm not available - this should never happen", e);
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Computes the WIT hash (wth).
     *
     * @param witJwtString the Workload Identity Token (JWT string)
     * @return the base64url-encoded SHA-256 hash of the WIT
     * @throws IllegalArgumentException if the WIT JWT string is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available
     */
    public static String computeWitHash(String witJwtString) {
        return computeSha256Hash(witJwtString);
    }

    /**
     * Computes the Access Token hash (ath).
     *
     * @param accessToken the access token
     * @return the base64url-encoded SHA-256 hash of the access token
     * @throws IllegalArgumentException if the access token is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available
     */
    public static String computeAccessTokenHash(String accessToken) {
        return computeSha256Hash(accessToken);
    }

    /**
     * Computes the Transaction Token hash (tth).
     *
     * @param transactionToken the transaction token
     * @return the base64url-encoded SHA-256 hash of the transaction token
     * @throws IllegalArgumentException if the transaction token is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available
     */
    public static String computeTransactionTokenHash(String transactionToken) {
        return computeSha256Hash(transactionToken);
    }

    /**
     * Computes the SHA-256 hash of a token used in the WPT oth (other tokens hashes) claim.
     *
     * @param aoatToken the token to hash (JWT string)
     * @return the base64url-encoded SHA-256 hash of the token
     * @throws IllegalArgumentException if the token is null or empty
     * @throws IllegalStateException if SHA-256 algorithm is not available
     */
    public static String computeAoatHash(String aoatToken) {
        return computeSha256Hash(aoatToken);
    }

    // Private constructor to prevent instantiation
    private JwtHashUtil() {
        throw new UnsupportedOperationException("Utility class cannot be instantiated");
    }
}