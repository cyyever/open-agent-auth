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
package com.alibaba.openagentauth.core.crypto.key;

import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.core.crypto.key.store.KeyStore;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.nimbusds.jose.jwk.JWK;

import java.util.List;

/**
 * Manages cryptographic keys: generation, storage, retrieval, rotation, and lifecycle.
 * All generated keys are Ed25519 ({@code alg=EdDSA}). Implementations must be thread-safe.
 *
 * @see KeyInfo
 * @see KeyStore
 * @since 1.0
 */
public interface KeyManager {

    /**
     * Generates and stores a new Ed25519 key pair under the given key ID.
     *
     * @throws KeyManagementException if generation fails or key ID already exists
     * @throws IllegalArgumentException if keyId is null or empty
     */
    void generateKeyPair(String keyId) throws KeyManagementException;

    Object getSigningJWK(String keyId) throws KeyManagementException;

    void rotateKey(String keyId) throws KeyManagementException;

    List<KeyInfo> getActiveKeys();

    boolean hasKey(String keyId);

    void deleteKey(String keyId) throws KeyManagementException;

    /**
     * Returns the existing signing JWK if present; otherwise generates a new Ed25519 key pair.
     */
    default Object getOrGenerateKey(String keyId) throws KeyManagementException {
        if (hasKey(keyId)) {
            return getSigningJWK(keyId);
        }
        generateKeyPair(keyId);
        return getSigningJWK(keyId);
    }

    default Object resolveKey(String keyId) throws KeyManagementException {
        return getSigningJWK(keyId);
    }

    default JWK resolveVerificationKey(String keyId) throws KeyManagementException {
        Object resolved = resolveKey(keyId);
        if (resolved instanceof JWK jwk) {
            return jwk;
        }
        throw new KeyManagementException(
                "Resolved key is not a JWK: " + (resolved != null ? resolved.getClass().getName() : "null"));
    }
}
