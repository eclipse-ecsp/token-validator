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

import org.eclipse.ecsp.tokenvalidator.AudienceValidator;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.util.List;

/**
 * Default audience validator that compares the token {@code aud} claim against
 * {@link PublicKeyInfo#getExpectedAudience()}.
 *
 * <p>Skips validation when {@code expectedAudience} is null. Accepts any-match semantics
 * for multi-value {@code aud} arrays: at least one element must equal the expected audience.
 *
 * @author Abhishek Kumar
 */
public class StandardAudienceValidator implements AudienceValidator {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(StandardAudienceValidator.class);

    /**
     * Constructs a new StandardAudienceValidator.
     */
    public StandardAudienceValidator() {
        // No-args constructor for bean registration in the Spring application context
    }

    /**
     * Validates the audience claim against the expected audience from {@link PublicKeyInfo}.
     *
     * <p>If {@code keyInfo.getExpectedAudience()} is null, validation is skipped.
     * Accepts a match if any element of a multi-value aud array equals the expected audience.
     *
     * @param audience the aud claim value (String or List of String, may be null)
     * @param keyInfo  the resolved PublicKeyInfo providing the expected audience
     * @throws InvalidClaimException if the audience is absent or does not match
     */
    @Override
    public void validate(Object audience, PublicKeyInfo keyInfo) throws InvalidClaimException {
        String expectedAudience = keyInfo.getExpectedAudience();
        if (expectedAudience == null) {
            LOGGER.debug("No expected audience configured for issuer {}; skipping aud validation",
                keyInfo.getIssuer());
            return;
        }
        if (audience == null) {
            throw new InvalidClaimException(
                "Token is missing 'aud' claim; expected: " + expectedAudience);
        }
        boolean matched = matchesAudience(audience, expectedAudience);
        if (!matched) {
            throw new InvalidClaimException(
                "Token audience does not match expected audience: " + expectedAudience);
        }
        LOGGER.debug("Audience validated successfully for issuer {}", keyInfo.getIssuer());
    }

    private boolean matchesAudience(Object audience, String expectedAudience) {
        if (audience instanceof List<?> list) {
            return list.stream()
                .anyMatch(el -> expectedAudience.equals(el != null ? el.toString() : null));
        }
        return expectedAudience.equals(audience.toString());
    }
}
