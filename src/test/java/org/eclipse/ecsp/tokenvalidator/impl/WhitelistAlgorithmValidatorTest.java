/********************************************************************************
 * Copyright (c) 2023-24 Harman International
 *
 * <p>Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * <p>http://www.apache.org/licenses/LICENSE-2.0
 *
 * <p>Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * <p>SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

package org.eclipse.ecsp.tokenvalidator.impl;

import org.eclipse.ecsp.tokenvalidator.exception.UnsupportedAlgorithmException;
import org.eclipse.ecsp.tokenvalidator.model.ParsedToken;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link WhitelistAlgorithmValidator}.
 *
 * @author Abhishek Kumar
 */
class WhitelistAlgorithmValidatorTest {

    private final WhitelistAlgorithmValidator validator =
        new WhitelistAlgorithmValidator(List.of("RS256", "ES256"));

    @Test
    void acceptsWhitelistedAlgorithm() {
        ParsedToken token = new ParsedToken("kid", "RS256", "iss", Map.of());
        assertDoesNotThrow(() -> validator.validate(token));
    }

    @Test
    void acceptsEs256() {
        ParsedToken token = new ParsedToken("kid", "ES256", "iss", Map.of());
        assertDoesNotThrow(() -> validator.validate(token));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"none", "NONE", "HS256"})
    void rejectsUnsupportedAlgorithm(String algorithm) {
        ParsedToken token = new ParsedToken("kid", algorithm, "iss", Map.of());
        assertThrows(UnsupportedAlgorithmException.class, () -> validator.validate(token));
    }

    @Test
    void defaultConstructorAllowsRs256AndEs256() {
        WhitelistAlgorithmValidator defaultValidator =
            new WhitelistAlgorithmValidator(List.of("RS256", "ES256"));
        ParsedToken token = new ParsedToken("kid", "RS256", "iss", Map.of());
        assertDoesNotThrow(() -> defaultValidator.validate(token));
    }
}
