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

import com.alibaba.openagentauth.core.crypto.key.model.KeyDefinition;
import com.alibaba.openagentauth.core.crypto.key.model.KeyInfo;
import com.alibaba.openagentauth.core.crypto.key.store.InMemoryKeyStore;
import com.alibaba.openagentauth.core.exception.crypto.KeyManagementException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetKeyPair;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for DefaultKeyManager.
 */
@DisplayName("DefaultKeyManager Tests")
class DefaultKeyManagerTest {

    private KeyManager keyManager;

    @BeforeEach
    void setUp() {
        keyManager = new DefaultKeyManager(new InMemoryKeyStore());
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should throw IllegalArgumentException when KeyStore is null")
        void shouldThrowExceptionWhenKeyStoreIsNull() {
            assertThatThrownBy(() -> new DefaultKeyManager(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("KeyStore cannot be null");
        }
    }

    @Nested
    @DisplayName("Key Generation Tests")
    class KeyGenerationTests {

        @Test
        @DisplayName("Should generate Ed25519 key pair")
        void shouldGenerateEd25519KeyPair() throws KeyManagementException {
            keyManager.generateKeyPair("test-key-001");

            assertThat(keyManager.hasKey("test-key-001")).isTrue();
            Object jwk = keyManager.getSigningJWK("test-key-001");
            assertThat(jwk).isInstanceOf(OctetKeyPair.class);
        }

        @Test
        @DisplayName("Should throw exception when keyId is null")
        void shouldThrowExceptionWhenKeyIdIsNull() {
            assertThatThrownBy(() -> keyManager.generateKeyPair(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty")
        void shouldThrowExceptionWhenKeyIdIsEmpty() {
            assertThatThrownBy(() -> keyManager.generateKeyPair(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is whitespace")
        void shouldThrowExceptionWhenKeyIdIsWhitespace() {
            assertThatThrownBy(() -> keyManager.generateKeyPair("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId already exists")
        void shouldThrowExceptionWhenKeyIdAlreadyExists() throws KeyManagementException {
            keyManager.generateKeyPair("test-key-008");

            assertThatThrownBy(() -> keyManager.generateKeyPair("test-key-008"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("already exists");
        }
    }

    @Nested
    @DisplayName("Key Retrieval Tests")
    class KeyRetrievalTests {

        @Test
        @DisplayName("Should retrieve Ed25519 signing JWK successfully")
        void shouldRetrieveEd25519SigningJwkSuccessfully() throws KeyManagementException {
            keyManager.generateKeyPair("test-jwk-okp-key");
            Object jwk = keyManager.getSigningJWK("test-jwk-okp-key");

            assertThat(jwk).isNotNull();
            assertThat(jwk).isInstanceOf(OctetKeyPair.class);
            OctetKeyPair okp = (OctetKeyPair) jwk;
            assertThat(okp.getKeyID()).isEqualTo("test-jwk-okp-key");
            assertThat(okp.getX()).isNotNull();
        }

        @Test
        @DisplayName("Should throw exception when JWK not found")
        void shouldThrowExceptionWhenJwkNotFound() {
            assertThatThrownBy(() -> keyManager.getSigningJWK("non-existent-jwk-key"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("JWK not found");
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for signing JWK")
        void shouldThrowExceptionWhenKeyIdIsNullForSigningJwk() {
            assertThatThrownBy(() -> keyManager.getSigningJWK(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty for signing JWK")
        void shouldThrowExceptionWhenKeyIdIsEmptyForSigningJwk() {
            assertThatThrownBy(() -> keyManager.getSigningJWK(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is whitespace for signing JWK")
        void shouldThrowExceptionWhenKeyIdIsWhitespaceForSigningJwk() {
            assertThatThrownBy(() -> keyManager.getSigningJWK("   "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Key Rotation Tests")
    class KeyRotationTests {

        @Test
        @DisplayName("Should rotate key successfully")
        void shouldRotateKeySuccessfully() throws KeyManagementException {
            keyManager.generateKeyPair("test-key-011");
            OctetKeyPair oldJwk = (OctetKeyPair) keyManager.getSigningJWK("test-key-011");

            keyManager.rotateKey("test-key-011");

            OctetKeyPair newJwk = (OctetKeyPair) keyManager.getSigningJWK("test-key-011");

            assertThat(newJwk).isNotNull();
            assertThat(newJwk.getX()).isNotEqualTo(oldJwk.getX());
        }

        @Test
        @DisplayName("Should throw exception when rotating non-existent key")
        void shouldThrowExceptionWhenRotatingNonExistentKey() {
            assertThatThrownBy(() -> keyManager.rotateKey("non-existent-key"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("Key not found for rotation");
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for rotation")
        void shouldThrowExceptionWhenKeyIdIsNullForRotation() {
            assertThatThrownBy(() -> keyManager.rotateKey(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty for rotation")
        void shouldThrowExceptionWhenKeyIdIsEmptyForRotation() {
            assertThatThrownBy(() -> keyManager.rotateKey(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Key Deletion Tests")
    class KeyDeletionTests {

        @Test
        @DisplayName("Should delete key successfully")
        void shouldDeleteKeySuccessfully() throws KeyManagementException {
            keyManager.generateKeyPair("test-key-012");
            assertThat(keyManager.hasKey("test-key-012")).isTrue();

            keyManager.deleteKey("test-key-012");
            assertThat(keyManager.hasKey("test-key-012")).isFalse();
        }

        @Test
        @DisplayName("Should throw exception when deleting non-existent key")
        void shouldThrowExceptionWhenDeletingNonExistentKey() {
            assertThatThrownBy(() -> keyManager.deleteKey("non-existent-key"))
                    .isInstanceOf(KeyManagementException.class)
                    .hasMessageContaining("Key not found for deletion");
        }

        @Test
        @DisplayName("Should throw exception when keyId is null for deletion")
        void shouldThrowExceptionWhenKeyIdIsNullForDeletion() {
            assertThatThrownBy(() -> keyManager.deleteKey(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw exception when keyId is empty for deletion")
        void shouldThrowExceptionWhenKeyIdIsEmptyForDeletion() {
            assertThatThrownBy(() -> keyManager.deleteKey(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }
    }

    @Nested
    @DisplayName("Key Existence Tests")
    class KeyExistenceTests {

        @Test
        @DisplayName("Should return true when key exists")
        void shouldReturnTrueWhenKeyExists() throws KeyManagementException {
            keyManager.generateKeyPair("test-key-013");

            assertThat(keyManager.hasKey("test-key-013")).isTrue();
        }

        @Test
        @DisplayName("Should return false when key does not exist")
        void shouldReturnFalseWhenKeyDoesNotExist() {
            assertThat(keyManager.hasKey("non-existent-key")).isFalse();
        }

        @Test
        @DisplayName("Should return false when keyId is null")
        void shouldReturnFalseWhenKeyIdIsNull() {
            assertThat(keyManager.hasKey(null)).isFalse();
        }

        @Test
        @DisplayName("Should return false when keyId is empty")
        void shouldReturnFalseWhenKeyIdIsEmpty() {
            assertThat(keyManager.hasKey("")).isFalse();
        }

        @Test
        @DisplayName("Should return false when keyId is whitespace")
        void shouldReturnFalseWhenKeyIdIsWhitespace() {
            assertThat(keyManager.hasKey("   ")).isFalse();
        }
    }

    @Nested
    @DisplayName("Active Keys Tests")
    class ActiveKeysTests {

        @Test
        @DisplayName("Should return list of active keys")
        void shouldReturnListOfActiveKeys() throws KeyManagementException {
            keyManager.generateKeyPair("test-key-014");
            keyManager.generateKeyPair("test-key-015");
            keyManager.generateKeyPair("test-key-016");

            List<KeyInfo> activeKeys = keyManager.getActiveKeys();

            assertThat(activeKeys).isNotNull();
            assertThat(activeKeys).hasSize(3);
            assertThat(activeKeys).allMatch(KeyInfo::isActive);
        }

        @Test
        @DisplayName("Should return empty list when no keys exist")
        void shouldReturnEmptyListWhenNoKeysExist() {
            List<KeyInfo> activeKeys = keyManager.getActiveKeys();

            assertThat(activeKeys).isNotNull();
            assertThat(activeKeys).isEmpty();
        }
    }

    @Nested
    @DisplayName("Thread Safety Tests")
    class ThreadSafetyTests {

        @Test
        @DisplayName("Should handle concurrent key generation")
        void shouldHandleConcurrentKeyGeneration() throws InterruptedException {
            int threadCount = 10;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executorService.submit(() -> {
                    try {
                        keyManager.generateKeyPair("concurrent-key-" + index);
                        successCount.incrementAndGet();
                    } catch (KeyManagementException e) {
                        // Expected for duplicate key IDs
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(successCount.get()).isGreaterThanOrEqualTo(threadCount - 5);

            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }

        @Test
        @DisplayName("Should handle concurrent key retrieval")
        void shouldHandleConcurrentKeyRetrieval() throws KeyManagementException, InterruptedException {
            keyManager.generateKeyPair("concurrent-retrieve-key");

            int threadCount = 20;
            ExecutorService executorService = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                executorService.submit(() -> {
                    try {
                        keyManager.getSigningJWK("concurrent-retrieve-key");
                        successCount.incrementAndGet();
                    } catch (KeyManagementException e) {
                        // Should not happen
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertThat(latch.await(30, TimeUnit.SECONDS)).isTrue();
            assertThat(successCount.get()).isEqualTo(threadCount);

            executorService.shutdown();
            executorService.awaitTermination(10, TimeUnit.SECONDS);
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should complete full key lifecycle")
        void shouldCompleteFullKeyLifecycle() throws KeyManagementException {
            keyManager.generateKeyPair("lifecycle-key");
            assertThat(keyManager.hasKey("lifecycle-key")).isTrue();

            Object jwk = keyManager.getSigningJWK("lifecycle-key");
            assertThat(jwk).isInstanceOf(OctetKeyPair.class);

            List<KeyInfo> activeKeys = keyManager.getActiveKeys();
            assertThat(activeKeys).hasSize(1);

            keyManager.deleteKey("lifecycle-key");
            assertThat(keyManager.hasKey("lifecycle-key")).isFalse();
        }

        @Test
        @DisplayName("Should handle multiple keys")
        void shouldHandleMultipleKeys() throws KeyManagementException {
            keyManager.generateKeyPair("multi-key-1");
            keyManager.generateKeyPair("multi-key-2");
            keyManager.generateKeyPair("multi-key-3");

            List<KeyInfo> activeKeys = keyManager.getActiveKeys();
            assertThat(activeKeys).hasSize(3);

            for (KeyInfo keyInfo : activeKeys) {
                assertThat(keyInfo.isActive()).isTrue();
                assertThat(keyInfo.getCreatedAt()).isNotNull();
                assertThat(keyInfo.getActivatedAt()).isNotNull();
            }
        }
    }

    @Nested
    @DisplayName("ResolveKey Tests")
    class ResolveKeyTests {

        @Test
        @DisplayName("Should fallback to getSigningJWK when no resolver chain exists")
        void shouldFallbackToGetSigningJWKWhenNoResolverChainExists() throws KeyManagementException {
            KeyManager singleParamManager = new DefaultKeyManager(new InMemoryKeyStore());
            singleParamManager.generateKeyPair("fallback-test-key");

            Object resolvedKey = singleParamManager.resolveKey("fallback-test-key");

            assertThat(resolvedKey).isNotNull();
            assertThat(resolvedKey).isInstanceOf(JWK.class);
            JWK jwk = (JWK) resolvedKey;
            assertThat(jwk.getKeyID()).isEqualTo("fallback-test-key");
        }

        @Test
        @DisplayName("Should resolve local key through resolver chain")
        void shouldResolveLocalKeyThroughResolverChain() throws KeyManagementException {
            Map<String, KeyDefinition> keyDefinitions = new HashMap<>();
            KeyDefinition keyDefinition = KeyDefinition.builder()
                    .keyId("local-resolver-key")
                    .provider("local")
                    .build();
            keyDefinitions.put("local-verification", keyDefinition);

            KeyManager threeParamManager = new DefaultKeyManager(
                new InMemoryKeyStore(),
                List.of(),
                keyDefinitions
            );

            threeParamManager.generateKeyPair("local-resolver-key");

            Object resolvedKey = threeParamManager.resolveKey("local-resolver-key");

            assertThat(resolvedKey).isNotNull();
            assertThat(resolvedKey).isInstanceOf(JWK.class);
            JWK jwk = (JWK) resolvedKey;
            assertThat(jwk.getKeyID()).isEqualTo("local-resolver-key");
        }

        @Test
        @DisplayName("Should find KeyDefinition by keyId field")
        void shouldFindKeyDefinitionByKeyIdField() throws KeyManagementException {
            Map<String, KeyDefinition> keyDefinitions = new HashMap<>();
            KeyDefinition keyDefinition = KeyDefinition.builder()
                    .keyId("wit-signing-key")
                    .provider("local")
                    .build();
            keyDefinitions.put("wit-verification", keyDefinition);

            KeyManager manager = new DefaultKeyManager(
                new InMemoryKeyStore(),
                List.of(),
                keyDefinitions
            );

            manager.generateKeyPair("wit-signing-key");

            Object resolvedKey = manager.resolveKey("wit-signing-key");

            assertThat(resolvedKey).isNotNull();
            assertThat(resolvedKey).isInstanceOf(JWK.class);
            JWK jwk = (JWK) resolvedKey;
            assertThat(jwk.getKeyID()).isEqualTo("wit-signing-key");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyId is null")
        void shouldThrowIllegalArgumentExceptionWhenKeyIdIsNull() {
            KeyManager manager = new DefaultKeyManager(new InMemoryKeyStore());

            assertThatThrownBy(() -> manager.resolveKey(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when keyId is empty")
        void shouldThrowIllegalArgumentExceptionWhenKeyIdIsEmpty() {
            KeyManager manager = new DefaultKeyManager(new InMemoryKeyStore());

            assertThatThrownBy(() -> manager.resolveKey(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Key ID cannot be null or empty");
        }

        @Test
        @DisplayName("Should not throw exception with null parameters in three-parameter constructor")
        void shouldNotThrowExceptionWithNullParametersInThreeParameterConstructor() {
            assertThatCode(() -> new DefaultKeyManager(
                new InMemoryKeyStore(),
                null,
                null
            )).doesNotThrowAnyException();
        }
    }
}
