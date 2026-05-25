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
 * <p>{@code StandardAudienceValidator} reads the expected audiences from
 * {@code PublicKeyInfo.expectedAudiences}, which is populated from
 * {@code PublicKeySource.audiences} at key-load time, enabling per-issuer audience enforcement.
 * When {@code expectedAudiences} is null or empty, validation is skipped for that issuer.
 *
 * @author Abhishek Kumar
 */
public interface AudienceValidator {

    /**
     * Validates the audience value extracted from the token.
     *
     * <p>When {@code keyInfo.getExpectedAudiences()} is null or empty, implementations must skip
     * validation. When non-null and non-empty, at least one element of the token {@code aud}
     * claim must match at least one element of the configured expected audiences.
     * The {@code aud} claim may be a single String or a JSON array of Strings (RFC 7519 §4.1.3).
     *
     * @param audience the aud claim value (may be null if absent; String or List of String)
     * @param keyInfo  the resolved PublicKeyInfo providing the expected audience
     * @throws InvalidClaimException if the audience is absent or no element matches
     */
    void validate(Object audience, PublicKeyInfo keyInfo) throws InvalidClaimException;
}
