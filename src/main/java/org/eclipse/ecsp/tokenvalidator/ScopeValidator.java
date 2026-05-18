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

package org.eclipse.ecsp.tokenvalidator;

import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import java.util.Arrays;
import java.util.List;

/**
 * Validates that a token's scope set satisfies an API route's required scopes.
 *
 * <p>Scope checking is opt-in and invoked by the caller after
 * {@link TokenValidator#validate(String)}.
 *
 * @author Abhishek Kumar
 */
public interface ScopeValidator {

    /**
     * Validates that every required scope is present in the token scopes.
     *
     * @param tokenScopes    scopes extracted from the validated token
     * @param requiredScopes scopes required by the API or route
     * @throws InvalidClaimException if one or more required scopes are missing
     */
    void validate(List<String> tokenScopes, List<String> requiredScopes)
        throws InvalidClaimException;

    /**
     * Convenience method that extracts scope strings from validated claims before
     * delegating to {@link #validate(List, List)}.
     *
     * <p>Looks for a claim named "scope" or "scp" and splits space-delimited values.
     * Both String and List values are handled.
     *
     * @param claims         the verified claims returned by the validation pipeline
     * @param requiredScopes scopes required by the API or route
     * @throws InvalidClaimException if one or more required scopes are missing
     */
    default void validateClaims(List<TokenClaim> claims, List<String> requiredScopes)
        throws InvalidClaimException {
        List<String> tokenScopes = claims.stream()
            .filter(c -> "scope".equals(c.getName()) || "scp".equals(c.getName()))
            .flatMap(c -> {
                Object val = c.getValue();
                if (val instanceof List<?> list) {
                    return list.stream().map(Object::toString);
                }
                return Arrays.stream(val.toString().split(" "));
            })
            .toList();
        validate(tokenScopes, requiredScopes);
    }
}
