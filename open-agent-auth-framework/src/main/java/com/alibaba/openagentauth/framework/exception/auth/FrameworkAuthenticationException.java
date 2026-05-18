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
package com.alibaba.openagentauth.framework.exception.auth;

/**
 * Exception thrown when authentication fails in framework orchestration layer.
 *
 * @since 1.0
 */
public class FrameworkAuthenticationException extends AuthException {

    /**
     * The error code for this exception.
     */
    private static final AuthErrorCode ERROR_CODE = AuthErrorCode.AUTHENTICATION_FAILED;

    /**
     * Constructs a new framework authentication exception with the specified detail message.
     *
     * @param message the detail message
     */
    public FrameworkAuthenticationException(String message) {
        super(ERROR_CODE, message);
    }

    /**
     * Constructs a new framework authentication exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public FrameworkAuthenticationException(String message, Throwable cause) {
        super(ERROR_CODE, cause, message);
    }
}
