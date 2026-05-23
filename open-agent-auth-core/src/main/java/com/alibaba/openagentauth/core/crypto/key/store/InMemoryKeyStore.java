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
package com.alibaba.openagentauth.core.crypto.key.store;

import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe in-memory {@link KeyStore} for dev / test. Stores Ed25519
 * {@code OctetKeyPair} JWKs in plain memory; not for production.
 */
public class InMemoryKeyStore implements KeyStore {

    private final ConcurrentHashMap<String, Object> jwkMap = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, KeyInfo> keyInfoMap = new ConcurrentHashMap<>();

    @Override
    public void storeJWK(String keyId, Object jwk, KeyInfo keyInfo) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        ValidationUtils.validateNotNull(jwk, "JWK");
        ValidationUtils.validateNotNull(keyInfo, "Key info");

        jwkMap.put(keyId, jwk);
        keyInfoMap.put(keyId, keyInfo);
    }

    @Override
    public Optional<Object> retrieveJWK(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        return Optional.ofNullable(jwkMap.get(keyId));
    }

    @Override
    public Optional<KeyInfo> retrieveInfo(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        return Optional.ofNullable(keyInfoMap.get(keyId));
    }

    @Override
    public boolean exists(String keyId) {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            return false;
        }
        return jwkMap.containsKey(keyId);
    }

    @Override
    public void delete(String keyId) throws KeyManagementException {
        if (ValidationUtils.isNullOrEmpty(keyId)) {
            throw new IllegalArgumentException("Key ID cannot be null or empty");
        }
        jwkMap.remove(keyId);
        keyInfoMap.remove(keyId);
    }

    @Override
    public List<String> listKeyIds() {
        return jwkMap.keySet().stream().toList();
    }

    @Override
    public void clear() throws KeyManagementException {
        jwkMap.clear();
        keyInfoMap.clear();
    }
}
