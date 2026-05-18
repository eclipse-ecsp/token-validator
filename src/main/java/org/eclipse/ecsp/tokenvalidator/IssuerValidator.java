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

import org.eclipse.ecsp.tokenvalidator.exception.InvalidIssuerException;

/**
 * Validates the issuer (iss) claim of a JWT independently.
 *
 * <p>Acts as an optional collaborator of {@code StandardTokenClaimsValidator} so that
 * issuer validation logic can be replaced without replacing the full claims validator.
 *
 * @author Abhishek Kumar
 */
public interface IssuerValidator {

    /**
     * Validates the issuer value extracted from the token.
     *
     * @param issuer the iss claim value (may be null if absent)
     * @throws InvalidIssuerException if the issuer is absent or not recognised
     */
    void validate(String issuer) throws InvalidIssuerException;
}
