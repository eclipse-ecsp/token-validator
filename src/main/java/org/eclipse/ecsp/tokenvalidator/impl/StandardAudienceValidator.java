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
import java.util.Objects;

/**
 * Default audience validator that compares the token {@code aud} claim against
 * {@link PublicKeyInfo#getExpectedAudiences()}.
 *
 * <p>Skips validation when {@code expectedAudiences} is null or empty. Accepts any-match
 * semantics: the token {@code aud} claim (single string or array) must contain at least
 * one value that is also present in the configured {@code expectedAudiences} list.
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
     * Validates the audience claim against the expected audiences from {@link PublicKeyInfo}.
     *
     * <p>If {@code keyInfo.getExpectedAudiences()} is null or empty, validation is skipped.
     * Accepts a match if any element of the token {@code aud} claim equals any element of
     * the configured expected audiences.
     *
     * @param audience the aud claim value (String or List of String, may be null)
     * @param keyInfo  the resolved PublicKeyInfo providing the expected audiences
     * @throws InvalidClaimException if the audience is absent or no token aud value matches
     *                               any configured expected audience
     */
    @Override
    public void validate(Object audience, PublicKeyInfo keyInfo) throws InvalidClaimException {
        List<String> expectedAudiences = keyInfo.getExpectedAudiences();
        if (expectedAudiences == null || expectedAudiences.isEmpty()) {
            LOGGER.debug("No expected audiences configured for issuer {}; skipping aud validation",
                keyInfo.getIssuer());
            return;
        }
        if (audience == null) {
            throw new InvalidClaimException(
                "Token is missing 'aud' claim; expected one of: " + expectedAudiences);
        }
        boolean matched = matchesAudience(audience, expectedAudiences);
        if (!matched) {
            throw new InvalidClaimException(
                "Token audience does not match any expected audience: " + expectedAudiences);
        }
        LOGGER.debug("Audience validated successfully for issuer {}", keyInfo.getIssuer());
    }

    private boolean matchesAudience(Object audience, List<String> expectedAudiences) {
        if (audience instanceof List<?> list) {
            return list.stream()
                .filter(Objects::nonNull)
                .map(Object::toString)
                .anyMatch(expectedAudiences::contains);
        }
        return expectedAudiences.contains(audience.toString());
    }
}
