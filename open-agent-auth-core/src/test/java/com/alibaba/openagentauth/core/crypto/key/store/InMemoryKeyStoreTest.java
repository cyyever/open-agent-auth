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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

class InMemoryKeyStoreTest {

    private static final String TEST_KEY_ID = "test-key-001";
    private static final String TEST_KEY_ID_2 = "test-key-002";
    private static final Instant NOW = Instant.now();

    private InMemoryKeyStore keyStore;
    private OctetKeyPair okpKey;
    private OctetKeyPair okpKey2;
    private KeyInfo keyInfo;

    @BeforeEach
    void setUp() throws JOSEException {
        keyStore = new InMemoryKeyStore();

        okpKey = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID(TEST_KEY_ID)
                .generate();

        okpKey2 = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID(TEST_KEY_ID_2)
                .generate();

        keyInfo = KeyInfo.builder()
                .keyId(TEST_KEY_ID)
                .createdAt(NOW)
                .activatedAt(NOW)
                .active(true)
                .build();
    }

    @Test
    void testStoreAndRetrieveJWK() throws KeyManagementException {
        keyStore.storeJWK(TEST_KEY_ID, okpKey, keyInfo);
        Optional<Object> retrievedJWK = keyStore.retrieveJWK(TEST_KEY_ID);

        assertThat(retrievedJWK).isPresent();
        assertThat(retrievedJWK.orElseThrow()).isInstanceOf(OctetKeyPair.class);
        OctetKeyPair retrieved = (OctetKeyPair) retrievedJWK.orElseThrow();
        assertThat(retrieved.getKeyID()).isEqualTo(TEST_KEY_ID);
    }

    @Test
    void testStoreAndRetrieveKeyInfo() throws KeyManagementException {
        keyStore.storeJWK(TEST_KEY_ID, okpKey, keyInfo);
        Optional<KeyInfo> retrievedKeyInfo = keyStore.retrieveInfo(TEST_KEY_ID);

        assertThat(retrievedKeyInfo).isPresent();
        assertThat(retrievedKeyInfo.orElseThrow()).isEqualTo(keyInfo);
        assertThat(retrievedKeyInfo.orElseThrow().getKeyId()).isEqualTo(TEST_KEY_ID);
        assertThat(retrievedKeyInfo.orElseThrow().isActive()).isTrue();
    }

    @Test
    void testRetrieveNonExistentKeyInfo() throws KeyManagementException {
        Optional<KeyInfo> retrievedKeyInfo = keyStore.retrieveInfo("non-existent-key");

        assertThat(retrievedKeyInfo).isEmpty();
    }

    @Test
    void testRetrieveNonExistentJWK() throws KeyManagementException {
        Optional<Object> retrievedJWK = keyStore.retrieveJWK("non-existent-key");

        assertThat(retrievedJWK).isEmpty();
    }

    @Test
    void testExists() throws KeyManagementException {
        assertThat(keyStore.exists(TEST_KEY_ID)).isFalse();

        keyStore.storeJWK(TEST_KEY_ID, okpKey, keyInfo);
        assertThat(keyStore.exists(TEST_KEY_ID)).isTrue();
    }

    @Test
    void testExistsWithNullKeyId() {
        assertThat(keyStore.exists(null)).isFalse();
    }

    @Test
    void testExistsWithEmptyKeyId() {
        assertThat(keyStore.exists("")).isFalse();
    }

    @Test
    void testDelete() throws KeyManagementException {
        keyStore.storeJWK(TEST_KEY_ID, okpKey, keyInfo);

        keyStore.delete(TEST_KEY_ID);

        assertThat(keyStore.exists(TEST_KEY_ID)).isFalse();
        assertThat(keyStore.retrieveInfo(TEST_KEY_ID)).isEmpty();
        assertThat(keyStore.retrieveJWK(TEST_KEY_ID)).isEmpty();
    }

    @Test
    void testDeleteWithNullKeyId() throws KeyManagementException {
        keyStore.storeJWK(TEST_KEY_ID, okpKey, keyInfo);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.delete(null))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testDeleteWithEmptyKeyId() throws KeyManagementException {
        keyStore.storeJWK(TEST_KEY_ID, okpKey, keyInfo);

        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.delete(""))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testListKeyIds() throws KeyManagementException {
        KeyInfo keyInfo2 = KeyInfo.builder()
                .keyId(TEST_KEY_ID_2)
                .createdAt(NOW)
                .activatedAt(NOW)
                .active(true)
                .build();

        keyStore.storeJWK(TEST_KEY_ID, okpKey, keyInfo);
        keyStore.storeJWK(TEST_KEY_ID_2, okpKey2, keyInfo2);

        List<String> keyIds = keyStore.listKeyIds();

        assertThat(keyIds).hasSize(2);
        assertThat(keyIds).containsExactlyInAnyOrder(TEST_KEY_ID, TEST_KEY_ID_2);
    }

    @Test
    void testListKeyIdsEmpty() {
        assertThat(keyStore.listKeyIds()).isEmpty();
    }

    @Test
    void testClear() throws KeyManagementException {
        KeyInfo keyInfo2 = KeyInfo.builder()
                .keyId(TEST_KEY_ID_2)
                .createdAt(NOW)
                .activatedAt(NOW)
                .active(true)
                .build();

        keyStore.storeJWK(TEST_KEY_ID, okpKey, keyInfo);
        keyStore.storeJWK(TEST_KEY_ID_2, okpKey2, keyInfo2);

        keyStore.clear();

        assertThat(keyStore.listKeyIds()).isEmpty();
        assertThat(keyStore.exists(TEST_KEY_ID)).isFalse();
        assertThat(keyStore.exists(TEST_KEY_ID_2)).isFalse();
    }

    @Test
    void testStoreJWKWithNullKeyId() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.storeJWK(null, okpKey, keyInfo))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testStoreJWKWithEmptyKeyId() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.storeJWK("", okpKey, keyInfo))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testStoreJWKWithNullJWK() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.storeJWK(TEST_KEY_ID, null, keyInfo))
                .withMessageContaining("JWK cannot be null");
    }

    @Test
    void testStoreJWKWithNullKeyInfo() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.storeJWK(TEST_KEY_ID, okpKey, null))
                .withMessageContaining("Key info cannot be null");
    }

    @Test
    void testRetrieveInfoWithNullKeyId() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.retrieveInfo(null))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testRetrieveJWKWithNullKeyId() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> keyStore.retrieveJWK(null))
                .withMessageContaining("Key ID cannot be null or empty");
    }

    @Test
    void testOverwriteExistingJWK() throws KeyManagementException, JOSEException {
        KeyInfo keyInfo1 = KeyInfo.builder()
                .keyId(TEST_KEY_ID)
                .createdAt(NOW.minusSeconds(3600))
                .activatedAt(NOW.minusSeconds(3600))
                .active(false)
                .build();

        keyStore.storeJWK(TEST_KEY_ID, okpKey, keyInfo1);

        OctetKeyPair rotated = new OctetKeyPairGenerator(Curve.Ed25519)
                .keyID(TEST_KEY_ID)
                .generate();
        KeyInfo keyInfo2 = KeyInfo.builder()
                .keyId(TEST_KEY_ID)
                .createdAt(NOW)
                .activatedAt(NOW)
                .active(true)
                .build();

        keyStore.storeJWK(TEST_KEY_ID, rotated, keyInfo2);

        Optional<Object> retrievedJWK = keyStore.retrieveJWK(TEST_KEY_ID);
        Optional<KeyInfo> retrievedKeyInfo = keyStore.retrieveInfo(TEST_KEY_ID);

        assertThat(retrievedJWK).isPresent();
        OctetKeyPair retrieved = (OctetKeyPair) retrievedJWK.orElseThrow();
        assertThat(retrieved.getX()).isEqualTo(rotated.getX());
        assertThat(retrievedKeyInfo).isPresent();
        assertThat(retrievedKeyInfo.orElseThrow().isActive()).isTrue();
        assertThat(retrievedKeyInfo.orElseThrow().getCreatedAt()).isEqualTo(NOW);
    }
}
