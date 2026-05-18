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

import org.eclipse.ecsp.tokenvalidator.ScopeMatchMode;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link DefaultScopeValidator}.
 *
 * @author Abhishek Kumar
 */
class DefaultScopeValidatorTest {

    @Test
    void requiredScopePresentPasses() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of());
        assertDoesNotThrow(() -> validator.validate(List.of("read", "write"), List.of("read")));
    }

    @Test
    void missingScopeThrows() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of());
        List<String> available = List.of("read");
        List<String> requiredScopes = List.of("write");
        assertThrows(InvalidClaimException.class, () -> validator.validate(available, requiredScopes));
    }

    @Test
    void prefixFilterRemovesNonMatchingScopes() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("api:"));
        List<String> nonMatchingScopes = List.of("read", "write");
        List<String> requiredFiltered = List.of("read");
        assertThrows(InvalidClaimException.class, () -> validator.validate(nonMatchingScopes, requiredFiltered));
    }

    @Test
    void prefixFilterKeepsMatchingScopes() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("api:"));
        assertDoesNotThrow(
            () -> validator.validate(List.of("api:read", "api:write"), List.of("api:read")));
    }

    @Test
    void validateClaimsExtractsScopeFromStringClaim() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of());
        List<TokenClaim> claims = List.of(new TokenClaim("scope", "read write"));
        assertDoesNotThrow(() -> validator.validateClaims(claims, List.of("read")));
    }

    @Test
    void validateClaimsExtractsScopeFromScpClaim() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of());
        List<TokenClaim> claims = List.of(new TokenClaim("scp", "read write"));
        assertDoesNotThrow(() -> validator.validateClaims(claims, List.of("write")));
    }

    @Test
    void validateClaimsMissingRequiredThrows() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of());
        List<TokenClaim> claims = List.of(new TokenClaim("scope", "read"));
        List<String> adminScope = List.of("admin");
        assertThrows(InvalidClaimException.class,
            () -> validator.validateClaims(claims, adminScope));
    }

    @Test
    void validateClaimsEmptyRequiredPasses() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of());
        List<TokenClaim> claims = List.of(new TokenClaim("scope", "read"));
        assertDoesNotThrow(() -> validator.validateClaims(claims, List.of()));
    }

    // --- ScopeMatchMode.ANY tests ---

    @Test
    void anyModeOneMatchingRequiredScopePasses() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of(), ScopeMatchMode.ANY);
        assertDoesNotThrow(() -> validator.validate(List.of("read", "write"), List.of("write", "admin")));
    }

    @Test
    void anyModeAllRequiredScopesPresentPasses() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of(), ScopeMatchMode.ANY);
        assertDoesNotThrow(() -> validator.validate(List.of("read", "write"), List.of("read", "write")));
    }

    @Test
    void anyModeNoneMatchingThrows() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of(), ScopeMatchMode.ANY);
        List<String> required = List.of("admin", "superuser");
        List<String> tokenScopes = List.of("read", "write");
        try { 
            validator.validate(tokenScopes, required);
            Assertions.fail("Expected InvalidClaimException to be thrown");
        } catch (InvalidClaimException e) {
            // Handle exception
            Assertions.assertTrue(e.getMessage()
                .contains("Token does not contain any of the required scopes: [admin, superuser]"));
        }
    }

    @Test
    void anyModeEmptyRequiredScopesDoesNotThrow() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of(), ScopeMatchMode.ANY);
        assertDoesNotThrow(() -> validator.validate(List.of("read"), List.of()));
    }

    @Test
    void anyModeWithPrefixFilterMatchPasses() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("api:"), ScopeMatchMode.ANY);
        assertDoesNotThrow(() -> validator.validate(
            List.of("api:read", "api:write"), List.of("api:write", "api:admin")));
    }

    @Test
    void anyModeWithPrefixFilterNoMatchThrows() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("api:"), ScopeMatchMode.ANY);
        List<String> required = List.of("api:admin");
        List<String> tokenScopes = List.of("api:read", "api:write");
        try {
            validator.validate(tokenScopes, required);
            Assertions.fail("Expected InvalidClaimException to be thrown");
        } catch (InvalidClaimException e) {
            Assertions.assertTrue(e.getMessage()
                .contains("Token does not contain any of the required scopes: [api:admin]"));
        }
    }

    @Test
    void anyModeNonPrefixScopesFilteredOutAndNoneMatchThrows() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("api:"), ScopeMatchMode.ANY);
        // token has "read" (no prefix match) and "api:write"; required is "api:read"
        List<String> required = List.of("api:read");
        List<String> tokenScopes = List.of("read", "api:write");
        try {
            validator.validate(tokenScopes, required);
            Assertions.fail("Expected InvalidClaimException to be thrown");
        } catch (InvalidClaimException e) {
            Assertions.assertTrue(e.getMessage()
                .contains("Token does not contain any of the required scopes: [api:read]"));
        }
    }

    @Test
    void anyModeValidateClaimsOneMatchPasses() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of(), ScopeMatchMode.ANY);
        List<TokenClaim> claims = List.of(new TokenClaim("scope", "read write"));
        assertDoesNotThrow(() -> validator.validateClaims(claims, List.of("write", "admin")));
    }

    @Test
    void anyModeValidateClaimsNoneMatchThrows() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of(), ScopeMatchMode.ANY);
        List<TokenClaim> claims = List.of(new TokenClaim("scope", "read write"));
        List<String> required = List.of("admin");
        try {
            validator.validateClaims(claims, required);
            Assertions.fail("Expected InvalidClaimException to be thrown");
        } catch (InvalidClaimException e) {
            Assertions.assertTrue(e.getMessage()
                .contains("Token does not contain any of the required scopes: [admin]"));
        }
    }
}
