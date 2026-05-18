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
import org.eclipse.ecsp.tokenvalidator.exception.InvalidIssuerException;
import org.eclipse.ecsp.tokenvalidator.exception.TokenExpiredException;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import java.util.List;

/**
 * Validates standard JWT claims after signature verification.
 *
 * <p>Always validates {@code exp}, {@code nbf}, and {@code iss}. Audience ({@code aud})
 * validation is delegated to the injected {@code AudienceValidator} when one is configured;
 * it is skipped otherwise.
 *
 * <p>{@code StandardTokenClaimsValidator} accepts a configurable {@code clockSkew} Duration
 * (default zero); the skew is applied symmetrically — {@code exp} is accepted if within
 * {@code clockSkew} after the current time, and {@code nbf} is accepted if within
 * {@code clockSkew} before the current time.
 * Step 5 of the validation pipeline.
 *
 * @author Abhishek Kumar
 */
public interface TokenClaimsValidator {

    /**
     * Validates standard claims on the provided verified claim list.
     *
     * @param claims verified claims from the token
     * @throws TokenExpiredException  if the exp claim is in the past beyond clockSkew tolerance
     * @throws InvalidClaimException  if nbf is in the future beyond clockSkew, aud is rejected,
     *                                or a required claim is missing
     * @throws InvalidIssuerException if the iss claim is absent or not recognised
     */
    void validate(List<TokenClaim> claims)
        throws TokenExpiredException, InvalidClaimException, InvalidIssuerException;
}
