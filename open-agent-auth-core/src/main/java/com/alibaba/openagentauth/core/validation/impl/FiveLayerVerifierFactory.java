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
package com.alibaba.openagentauth.core.validation.impl;

import com.alibaba.openagentauth.core.binding.BindingInstanceStore;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.util.ValidationUtils;
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.validation.api.FiveLayerVerifier;
import com.alibaba.openagentauth.core.validation.layer.OperationAuthorizationValidator;
import com.alibaba.openagentauth.core.validation.layer.IdentityConsistencyValidator;
import com.alibaba.openagentauth.core.validation.layer.WorkloadIdentityValidator;
import com.alibaba.openagentauth.core.validation.layer.WorkloadProofValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory that assembles the layered resource-server verifier.
 *
 * <h3>Validators registered (in execution order):</h3>
 * <ol>
 *   <li>{@link WorkloadIdentityValidator} - WIT signature and claims</li>
 *   <li>{@link WorkloadProofValidator} - WPT signature and integrity</li>
 *   <li>{@link OperationAuthorizationValidator} - AOAT signature and claims</li>
 *   <li>{@link IdentityConsistencyValidator} - user/workload identity binding</li>
 * </ol>
 *
 * @since 1.0
 */
public class FiveLayerVerifierFactory {

    private static final Logger logger = LoggerFactory.getLogger(FiveLayerVerifierFactory.class);

    public static FiveLayerVerifier createVerifier(WitValidator witValidator,
                                                   WptValidator wptValidator,
                                                   AoatValidator aoatValidator,
                                                   BindingInstanceStore bindingInstanceStore) {

        ValidationUtils.validateNotNull(witValidator, "WIT validator");
        ValidationUtils.validateNotNull(wptValidator, "WPT validator");
        ValidationUtils.validateNotNull(aoatValidator, "AOAT validator");

        DefaultFiveLayerVerifier verifier = new DefaultFiveLayerVerifier();

        verifier.registerValidator(new WorkloadIdentityValidator(witValidator));
        verifier.registerValidator(new WorkloadProofValidator(wptValidator));
        verifier.registerValidator(new OperationAuthorizationValidator(aoatValidator));
        verifier.registerValidator(new IdentityConsistencyValidator(bindingInstanceStore));

        logger.info("Layered verifier created with 4 validators (policy layer removed)");
        return verifier;
    }
}
