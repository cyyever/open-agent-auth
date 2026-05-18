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
package com.alibaba.openagentauth.core.validation.api;

import com.alibaba.openagentauth.core.validation.model.ValidationContext;
import com.alibaba.openagentauth.core.validation.model.LayerValidationResult;

/**
 * Interface for a single layer validator.
 * Validators are executed in sequence; any failure causes the entire verification to fail.
 *
 * @see ValidationContext
 * @see LayerValidationResult
 * @since 1.0
 */
public interface LayerValidator {

    /**
     * Validates the given validation context.
     *
     * @param context the validation context containing all necessary information
     * @return the validation result with success/failure status and error messages
     * @throws IllegalArgumentException if the context is null or missing required information
     */
    LayerValidationResult validate(ValidationContext context);

    /**
     * Gets the name of this validator, used for logging and error reporting.
     *
     * @return the validator name
     */
    String getName();

    /**
     * Gets the order of this validator in the verification pipeline.
     * Lower numbers run earlier.
     *
     * @return the execution order
     */
    default double getOrder() {
        return 0;
    }
}
