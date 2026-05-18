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

import org.eclipse.ecsp.tokenvalidator.exception.InvalidIssuerException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link StandardIssuerValidator}.
 *
 * @author Abhishek Kumar
 */
class StandardIssuerValidatorTest {

    @Test
    void validIssuerPasses() {
        StandardIssuerValidator validator =
            new StandardIssuerValidator(Set.of("https://issuer.example.com"));
        assertDoesNotThrow(() -> validator.validate("https://issuer.example.com"));
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"https://evil.example.com", "  "})
    void invalidIssuerThrows(String issuer) {
        StandardIssuerValidator validator =
            new StandardIssuerValidator(Set.of("https://issuer.example.com"));
        assertThrows(InvalidIssuerException.class, () -> validator.validate(issuer));
    }

    @Test
    void emptyAllowListThrowsForAnyIssuer() {
        StandardIssuerValidator validator = new StandardIssuerValidator(Set.of());
        assertThrows(InvalidIssuerException.class, () -> validator.validate("any-issuer"));
    }
}
