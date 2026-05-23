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
package com.alibaba.openagentauth.core.crypto.key.resolve;

import com.alibaba.openagentauth.core.crypto.key.KeyManager;
import com.alibaba.openagentauth.core.crypto.key.model.KeyDefinition;
import com.alibaba.openagentauth.core.exception.crypto.KeyResolutionException;
import com.nimbusds.jose.jwk.JWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link KeyResolver} backed by the local {@link KeyManager}. If the key is not yet
 * present, an Ed25519 key pair is generated on demand.
 *
 * <p><b>Priority:</b> 0 (highest — local keys are checked first)</p>
 *
 * @since 1.0
 */
public class LocalKeyResolver implements KeyResolver {

    private static final Logger logger = LoggerFactory.getLogger(LocalKeyResolver.class);

    private final KeyManager keyManager;

    public LocalKeyResolver(KeyManager keyManager) {
        if (keyManager == null) {
            throw new IllegalArgumentException("KeyManager cannot be null");
        }
        this.keyManager = keyManager;
    }

    @Override
    public boolean supports(KeyDefinition keyDefinition) {
        return keyDefinition != null && keyDefinition.isLocalKey();
    }

    @Override
    public JWK resolve(KeyDefinition keyDefinition) throws KeyResolutionException {
        String keyId = keyDefinition.getKeyId();
        logger.debug("Resolving local key: keyId={}", keyId);

        try {
            Object jwk = keyManager.getOrGenerateKey(keyId);

            if (!(jwk instanceof JWK)) {
                throw new KeyResolutionException(
                        "Resolved object is not a JWK instance for key: " + keyId);
            }

            logger.debug("Successfully resolved local key: keyId={}", keyId);
            return (JWK) jwk;
        } catch (KeyResolutionException e) {
            throw e;
        } catch (Exception e) {
            throw new KeyResolutionException(
                    "Failed to resolve local key '" + keyId + "': " + e.getMessage(), e);
        }
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
