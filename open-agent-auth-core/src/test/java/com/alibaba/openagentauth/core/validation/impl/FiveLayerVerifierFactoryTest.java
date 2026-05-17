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
import com.alibaba.openagentauth.core.protocol.wimse.wit.WitValidator;
import com.alibaba.openagentauth.core.protocol.wimse.wpt.WptValidator;
import com.alibaba.openagentauth.core.token.aoat.AoatValidator;
import com.alibaba.openagentauth.core.validation.api.FiveLayerVerifier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
@DisplayName("FiveLayerVerifierFactory Tests")
class FiveLayerVerifierFactoryTest {

    @Mock
    private WitValidator witValidator;

    @Mock
    private WptValidator wptValidator;

    @Mock
    private AoatValidator aoatValidator;

    @Mock
    private BindingInstanceStore bindingInstanceStore;

    @Nested
    @DisplayName("Successful Creation Tests")
    class SuccessfulCreationTests {

        @Test
        void shouldCreateVerifierWithoutBindingStore() {
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator, wptValidator, aoatValidator, null);

            assertThat(verifier).isInstanceOf(DefaultFiveLayerVerifier.class);
        }

        @Test
        void shouldCreateVerifierWithBindingStore() {
            FiveLayerVerifier verifier = FiveLayerVerifierFactory.createVerifier(
                    witValidator, wptValidator, aoatValidator, bindingInstanceStore);

            assertThat(verifier).isInstanceOf(DefaultFiveLayerVerifier.class);
        }

        @Test
        void shouldCreateNewVerifierInstanceEachTime() {
            FiveLayerVerifier v1 = FiveLayerVerifierFactory.createVerifier(
                    witValidator, wptValidator, aoatValidator, null);
            FiveLayerVerifier v2 = FiveLayerVerifierFactory.createVerifier(
                    witValidator, wptValidator, aoatValidator, null);

            assertThat(v1).isNotSameAs(v2);
        }
    }

    @Nested
    @DisplayName("Parameter Validation Tests")
    class ParameterValidationTests {

        @Test
        void shouldThrowWhenWitValidatorIsNull() {
            assertThatThrownBy(() -> FiveLayerVerifierFactory.createVerifier(
                    null, wptValidator, aoatValidator, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WIT validator");
        }

        @Test
        void shouldThrowWhenWptValidatorIsNull() {
            assertThatThrownBy(() -> FiveLayerVerifierFactory.createVerifier(
                    witValidator, null, aoatValidator, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("WPT validator");
        }

        @Test
        void shouldThrowWhenAoatValidatorIsNull() {
            assertThatThrownBy(() -> FiveLayerVerifierFactory.createVerifier(
                    witValidator, wptValidator, null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("AOAT validator");
        }
    }
}
