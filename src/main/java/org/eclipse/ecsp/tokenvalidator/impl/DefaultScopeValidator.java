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
import org.eclipse.ecsp.tokenvalidator.ScopeValidator;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Default scope validator that filters token scopes by prefix and checks required scopes.
 *
 * <p>Constructor accepts a set of scope prefixes; only token scopes matching one of the
 * prefixes are considered. Pass an empty set to accept all scopes without filtering.
 *
 * <p>The matching behaviour is controlled by {@link ScopeMatchMode}:
 * <ul>
 *   <li>{@link ScopeMatchMode#ALL} (default) — every required scope must be present in the
 *       filtered token scopes. Validation fails if even one required scope is absent.</li>
 *   <li>{@link ScopeMatchMode#ANY} — at least one required scope must be present in the
 *       filtered token scopes. Validation passes as soon as any match is found.</li>
 * </ul>
 *
 * @author Abhishek Kumar
 */
public class DefaultScopeValidator implements ScopeValidator {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(DefaultScopeValidator.class);

    private final Set<String> scopePrefixes;
    private final ScopeMatchMode matchMode;

    /**
     * Constructs a DefaultScopeValidator with the given scope prefixes and {@link ScopeMatchMode#ALL}
     * match mode (all required scopes must be present).
     *
     * @param scopePrefixes the set of scope prefixes to filter by; pass empty set to accept all
     */
    public DefaultScopeValidator(Set<String> scopePrefixes) {
        this(scopePrefixes, ScopeMatchMode.ALL);
    }

    /**
     * Constructs a DefaultScopeValidator with the given scope prefixes and match mode.
     *
     * @param scopePrefixes the set of scope prefixes to filter by; pass empty set to accept all
     * @param matchMode     {@link ScopeMatchMode#ALL} to require every listed scope,
     *                      or {@link ScopeMatchMode#ANY} to require at least one
     */
    public DefaultScopeValidator(Set<String> scopePrefixes, ScopeMatchMode matchMode) {
        this.scopePrefixes = Set.copyOf(scopePrefixes);
        this.matchMode = matchMode;
    }

    /**
     * Validates that the token scopes satisfy the required scopes according to the configured
     * {@link ScopeMatchMode}.
     *
     * <p>Token scopes are first filtered by the configured prefixes (unless prefixes is empty).
     * In {@link ScopeMatchMode#ALL} mode every required scope must be present; in
     * {@link ScopeMatchMode#ANY} mode at least one required scope must be present.
     *
     * @param tokenScopes    scopes extracted from the validated token
     * @param requiredScopes scopes required by the API or route
     * @throws InvalidClaimException if the token scopes do not satisfy the required scopes
     */
    @Override
    public void validate(List<String> tokenScopes, List<String> requiredScopes)
        throws InvalidClaimException {
        Set<String> filtered = filterScopes(tokenScopes);
        if (matchMode == ScopeMatchMode.ANY) {
            validateAny(filtered, requiredScopes);
        } else {
            validateAll(filtered, requiredScopes);
        }
    }

    private void validateAll(Set<String> filtered, List<String> requiredScopes)
        throws InvalidClaimException {
        List<String> missing = requiredScopes.stream()
            .filter(required -> !filtered.contains(required))
            .toList();
        if (!missing.isEmpty()) {
            throw new InvalidClaimException(
                "Token is missing required scopes: " + missing);
        }
        LOGGER.debug("Scope validation passed (ALL mode): all required scopes present");
    }

    private void validateAny(Set<String> filtered, List<String> requiredScopes)
        throws InvalidClaimException {
        if (requiredScopes.isEmpty()) {
            return;
        }
        boolean anyMatch = requiredScopes.stream().anyMatch(filtered::contains);
        if (!anyMatch) {
            throw new InvalidClaimException(
                "Token does not contain any of the required scopes: " + requiredScopes);
        }
        LOGGER.debug("Scope validation passed (ANY mode): at least one required scope present");
    }

    private Set<String> filterScopes(List<String> tokenScopes) {
        if (scopePrefixes.isEmpty()) {
            return Set.copyOf(tokenScopes);
        }
        return tokenScopes.stream()
            .flatMap(scope -> scopePrefixes.stream()
                .filter(scope::startsWith)
                .map(prefix -> scope.substring(prefix.length()))
                .limit(1))
            .collect(Collectors.toUnmodifiableSet());
    }
}
