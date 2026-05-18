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

import com.nimbusds.jose.JOSEException;

/**
 * Interface for tokens that can be bound to a Workload Proof Token (WPT)
 * via the oth (other tokens hashes) claim.
 *
 * @since 1.0
 */
public interface OthBindableToken {

    /**
     * Returns the JWT string representation of this token, used to compute the SHA-256
     * hash included in the WPT's oth claim.
     *
     * @return the complete JWT string (header.payload.signature)
     * @throws JOSEException if the JWT string is not available or cannot be retrieved
     */
    String getJwtString() throws JOSEException;

    /**
     * Returns the token type identifier used as the key in the oth claim's JSON object.
     *
     * @return the token type identifier
     */
    String getTokenType();

}
