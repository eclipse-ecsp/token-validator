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
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;

/**
 * Optional validator for the audience (aud) claim of a JWT.
 *
 * <p>Injected into {@code StandardTokenClaimsValidator}; when no AudienceValidator is configured
 * the {@code aud} claim is not validated and the token is accepted regardless of its aud value.
 *
 * <p>{@code StandardAudienceValidator} reads the expected audience from
 * {@code PublicKeyInfo.expectedAudience}, which is populated from
 * {@code PublicKeySource.audience} at key-load time, enabling per-issuer audience enforcement.
 * When {@code expectedAudience} is null, validation is skipped for that issuer.
 *
 * @author Abhishek Kumar
 */
public interface AudienceValidator {

    /**
     * Validates the audience value extracted from the token.
     *
     * <p>When {@code keyInfo.getExpectedAudience()} is null, implementations must skip validation.
     * When non-null, the token {@code aud} claim must match. The {@code aud} claim may be a single
     * String or a JSON array of Strings (RFC 7519 §4.1.3). Accepts a match if any element of a
     * multi-value {@code aud} array equals the expected audience.
     *
     * @param audience the aud claim value (may be null if absent; String or List of String)
     * @param keyInfo  the resolved PublicKeyInfo providing the expected audience
     * @throws InvalidClaimException if the audience is absent or no element matches
     */
    void validate(Object audience, PublicKeyInfo keyInfo) throws InvalidClaimException;
}
