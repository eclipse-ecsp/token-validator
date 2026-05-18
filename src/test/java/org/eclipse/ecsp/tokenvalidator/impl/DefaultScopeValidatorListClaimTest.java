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

import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Additional coverage tests for {@link DefaultScopeValidator} list claim handling.
 *
 * @author Abhishek Kumar
 */
class DefaultScopeValidatorListClaimTest {

    @Test
    void validateClaimsExtractsScopeFromListClaim() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of());
        List<TokenClaim> claims = List.of(new TokenClaim("scope", List.of("read", "write")));
        assertDoesNotThrow(() -> validator.validateClaims(claims, List.of("read")));
    }

    @Test
    void validateClaimsWithNoScopeClaim() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of());
        List<TokenClaim> claims = List.of(new TokenClaim("sub", "user1"));
        List<String> required = List.of("read");
        assertThrows(InvalidClaimException.class,
            () -> validator.validateClaims(claims, required));
    }

    @Test
    void validateClaimsScpListClaim() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of());
        List<TokenClaim> claims = List.of(new TokenClaim("scp", List.of("admin")));
        assertDoesNotThrow(() -> validator.validateClaims(claims, List.of("admin")));
    }

    @Test
    void validateDirectStringScpNoPrefix() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of());
        assertDoesNotThrow(() -> validator.validate(List.of("read", "write"), List.of("write")));
    }
}
