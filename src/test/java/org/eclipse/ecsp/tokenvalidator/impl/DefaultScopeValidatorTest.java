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
    void prefixFilterKeepsNonMatchingScopesAsIs() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("api:"));
        // scopes without a matching prefix are kept as-is, so "read" is still present
        List<String> nonMatchingScopes = List.of("read", "write");
        List<String> requiredFiltered = List.of("read");
        assertDoesNotThrow(() -> validator.validate(nonMatchingScopes, requiredFiltered));
    }

    @Test
    void prefixFilterKeepsMatchingScopes() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("api:"));
        // prefix is stripped: "api:read" → "read", required scope must be without prefix
        assertDoesNotThrow(
            () -> validator.validate(List.of("api:read", "api:write"), List.of("read")));
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
        // prefix is stripped: "api:write" → "write", required scope must be without prefix
        assertDoesNotThrow(() -> validator.validate(
            List.of("api:read", "api:write"), List.of("write", "admin")));
    }

    @Test
    void anyModeWithPrefixFilterNoMatchThrows() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("api:"), ScopeMatchMode.ANY);
        // prefix stripped: filtered set is {"read", "write"}, "admin" is not present
        List<String> required = List.of("admin");
        List<String> tokenScopes = List.of("api:read", "api:write");
        try {
            validator.validate(tokenScopes, required);
            Assertions.fail("Expected InvalidClaimException to be thrown");
        } catch (InvalidClaimException e) {
            Assertions.assertTrue(e.getMessage()
                .contains("Token does not contain any of the required scopes: [admin]"));
        }
    }

    @Test
    void anyModeNonPrefixScopesKeptAsIsAndNoneMatchThrows() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("api:"), ScopeMatchMode.ANY);
        // "read" has no prefix match → kept as-is; "api:write" → stripped to "write"
        // filtered = {"read", "write"}; "admin" is not present so validation still fails
        List<String> required = List.of("admin");
        List<String> tokenScopes = List.of("read", "api:write");
        try {
            validator.validate(tokenScopes, required);
            Assertions.fail("Expected InvalidClaimException to be thrown");
        } catch (InvalidClaimException e) {
            Assertions.assertTrue(e.getMessage()
                .contains("Token does not contain any of the required scopes: [admin]"));
        }
    }

    @Test
    void anyModeValidateClaimsOneMatchPasses() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of(), ScopeMatchMode.ANY);
        List<TokenClaim> claims = List.of(new TokenClaim("scope", "read write"));
        assertDoesNotThrow(() -> validator.validateClaims(claims, List.of("write", "admin")));
    }

    // --- Prefix stripping tests ---

    @Test
    void prefixIsStrippedFromMatchingScope() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("abc/", "xyz/"));
        // "abc/Scope1" → "Scope1", "xyz/Scope2" → "Scope2"; required without prefix
        assertDoesNotThrow(() -> validator.validate(
            List.of("abc/Scope1", "xyz/Scope2"), List.of("Scope1", "Scope2")));
    }

    @Test
    void prefixStrippedScopeNotMatchedByOriginalName() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("abc/"));
        List<String> tokenScopes = List.of("abc/Scope1");
        List<String> required = List.of("abc/Scope1");
        try {
            validator.validate(tokenScopes, required);
            Assertions.fail("Expected InvalidClaimException to be thrown");
        } catch (InvalidClaimException e) {
            Assertions.assertTrue(e.getMessage()
                .contains("Token is missing required scopes: [abc/Scope1]"));
        }
    }

    @Test
    void scopeWithoutMatchingPrefixIsExcluded() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("abc/"));
        // "other/Scope" has no matching prefix → excluded; required "Scope" not in filtered set
        List<String> required = List.of("Scope");
        List<String> tokenScopes = List.of("other/Scope");
        try {
            validator.validate(tokenScopes, required);
            Assertions.fail("Expected InvalidClaimException to be thrown");
        } catch (InvalidClaimException e) {
            Assertions.assertTrue(e.getMessage()
                .contains("Token is missing required scopes: [Scope]"));
        }
    }

    @Test
    void multiplePrefixesBothStrippedAllMode() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("abc/", "xyz/"));
        // abc/Read → Read, xyz/Write → Write; require both
        assertDoesNotThrow(() -> validator.validate(
            List.of("abc/Read", "xyz/Write", "other/Admin"), List.of("Read", "Write")));
    }

    @Test
    void multiplePrefixesAnyModeStrippedScopeMatches() {
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("abc/", "xyz/"), ScopeMatchMode.ANY);
        // abc/Read → Read; required ["Read", "Admin"] — "Read" matches
        assertDoesNotThrow(() -> validator.validate(
            List.of("abc/Read", "xyz/Write"), List.of("Read", "Admin")));
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

    @Test
    void anyModeUnprefixedScopeMatchesRequiredWhenPrefixConfigured() {
        // Token has "SelfManage" (no prefix); required is also "SelfManage".
        // With a prefix configured, the scope has no matching prefix and is kept as-is,
        // so it must still satisfy the ANY-mode required scope check.
        DefaultScopeValidator validator = new DefaultScopeValidator(Set.of("vehicle:"), ScopeMatchMode.ANY);
        assertDoesNotThrow(() -> validator.validate(List.of("SelfManage"), List.of("SelfManage")));
    }
}
