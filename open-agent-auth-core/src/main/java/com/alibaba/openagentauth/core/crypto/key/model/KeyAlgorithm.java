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
package com.alibaba.openagentauth.core.crypto.key.model;

import com.nimbusds.jose.JWSAlgorithm;

/**
 * Enumeration of supported key algorithms for cryptographic operations.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518">RFC 7518 - JSON Web Algorithms (JWA)</a>
 * @since 1.0
 */
public enum KeyAlgorithm {
    
    /**
     * RSASSA-PKCS1-v1_5 using SHA-256.
     * <p>
     * RSA 2048-bit keys with SHA-256 hashing.
     * </p>
     */
    RS256(JWSAlgorithm.RS256, "RSA", 2048),
    
    /**
     * RSASSA-PKCS1-v1_5 using SHA-384.
     * <p>
     * RSA 3072-bit keys with SHA-384 hashing.
     * </p>
     */
    RS384(JWSAlgorithm.RS384, "RSA", 3072),
    
    /**
     * RSASSA-PKCS1-v1_5 using SHA-512.
     * <p>
     * RSA 4096-bit keys with SHA-512 hashing.
     * </p>
     */
    RS512(JWSAlgorithm.RS512, "RSA", 4096),
    
    /**
     * ECDSA using P-256 and SHA-256.
     * <p>
     * Elliptic Curve P-256 with SHA-256 hashing.
     * </p>
     */
    ES256(JWSAlgorithm.ES256, "EC", 256),
    
    /**
     * ECDSA using P-384 and SHA-384.
     * <p>
     * Elliptic Curve P-384 with SHA-384 hashing.
     * </p>
     */
    ES384(JWSAlgorithm.ES384, "EC", 384),
    
    /**
     * ECDSA using P-521 and SHA-512.
     * <p>
     * Elliptic Curve P-521 with SHA-512 hashing.
     * </p>
     */
    ES512(JWSAlgorithm.ES512, "EC", 521);
    
    /**
     * The corresponding JWS algorithm.
     */
    private final JWSAlgorithm jwsAlgorithm;
    
    /**
     * The key type (RSA or EC).
     */
    private final String keyType;
    
    /**
     * The recommended key size in bits.
     */
    private final int keySize;
    
    /**
     * Creates a new KeyAlgorithm.
     *
     * @param jwsAlgorithm the JWS algorithm
     * @param keyType the key type
     * @param keySize the recommended key size
     */
    KeyAlgorithm(JWSAlgorithm jwsAlgorithm, String keyType, int keySize) {
        this.jwsAlgorithm = jwsAlgorithm;
        this.keyType = keyType;
        this.keySize = keySize;
    }
    
    /**
     * Gets the JWS algorithm.
     *
     * @return the JWS algorithm
     */
    public JWSAlgorithm getJwsAlgorithm() {
        return jwsAlgorithm;
    }
    
    /**
     * Gets the key type.
     *
     * @return the key type (RSA or EC)
     */
    public String getKeyType() {
        return keyType;
    }
    
    /**
     * Gets the recommended key size.
     *
     * @return the key size in bits
     */
    public int getKeySize() {
        return keySize;
    }
    
    /**
     * Checks if this is an RSA algorithm.
     *
     * @return true if RSA algorithm, false otherwise
     */
    public boolean isRsa() {
        return "RSA".equals(keyType);
    }
    
    /**
     * Checks if this is an EC algorithm.
     *
     * @return true if EC algorithm, false otherwise
     */
    public boolean isEc() {
        return "EC".equals(keyType);
    }
    
    /**
     * Gets the KeyAlgorithm from the JWS algorithm name.
     *
     * @param jwsAlgorithmName the JWS algorithm name (e.g., "RS256", "ES256")
     * @return the corresponding KeyAlgorithm
     * @throws IllegalArgumentException if the algorithm name is not recognized
     */
    public static KeyAlgorithm fromValue(String jwsAlgorithmName) {
        if (jwsAlgorithmName == null || jwsAlgorithmName.isBlank()) {
            throw new IllegalArgumentException("JWS algorithm name cannot be null or empty");
        }
        
        for (KeyAlgorithm algorithm : values()) {
            if (algorithm.jwsAlgorithm.getName().equals(jwsAlgorithmName)) {
                return algorithm;
            }
        }
        
        throw new IllegalArgumentException("No matching KeyAlgorithm for JWS algorithm: " + jwsAlgorithmName);
    }
}
