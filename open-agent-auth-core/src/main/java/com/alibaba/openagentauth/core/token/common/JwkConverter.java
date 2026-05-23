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

import com.alibaba.openagentauth.core.model.jwk.Jwk;
import com.alibaba.openagentauth.core.util.ValidationUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for converting between JWK maps and Jwk model objects.
 */
public class JwkConverter {

    public static Jwk convertMapToJwk(Map<String, Object> jwkMap) {

        Jwk.Builder builder = Jwk.builder();

        String ktyValue = getClaimAsString(jwkMap, "kty");
        ValidationUtils.validateNotNull(ktyValue, "Missing required 'kty' (key type) parameter in JWK");
        builder.keyType(Jwk.KeyType.fromValue(ktyValue));

        String use = getClaimAsString(jwkMap, "use");
        if (use != null) {
            builder.use(Jwk.KeyUse.fromValue(use));
        }

        String crv = getClaimAsString(jwkMap, "crv");
        if (crv != null) {
            builder.curve(Jwk.Curve.fromValue(crv));
        }

        String x = getClaimAsString(jwkMap, "x");
        if (x != null) {
            builder.x(x);
        }

        String kid = getClaimAsString(jwkMap, "kid");
        if (kid != null) {
            builder.keyId(kid);
        }

        return builder.build();
    }

    public static String getClaimAsString(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof String) {
            return (String) value;
        }
        throw new IllegalArgumentException("Invalid claim '%s': expected String, got %s"
                .formatted(key, value.getClass().getSimpleName()));
    }

    public static Map<String, Object> convertJwkToMap(Jwk jwk) {

        Map<String, Object> jwkMap = new HashMap<>();

        jwkMap.put("kty", jwk.keyType().getValue());
        jwkMap.put("alg", "EdDSA");
        jwkMap.put("crv", jwk.curve().getValue());
        jwkMap.put("x", jwk.x());

        if (jwk.use() != null) {
            jwkMap.put("use", jwk.use().getValue());
        }
        if (jwk.keyId() != null) {
            jwkMap.put("kid", jwk.keyId());
        }

        return jwkMap;
    }
}
