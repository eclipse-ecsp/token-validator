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

import org.eclipse.ecsp.tokenvalidator.IssuerValidator;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidIssuerException;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.util.Set;

/**
 * Default issuer validator that checks against a configured set of known issuers.
 *
 * <p>Validates the {@code iss} claim against a {@link Set} of known issuers
 * derived from configured {@code PublicKeySource} entries.
 *
 * @author Abhishek Kumar
 */
public class StandardIssuerValidator implements IssuerValidator {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(StandardIssuerValidator.class);

    private final Set<String> knownIssuers;

    /**
     * Constructs a StandardIssuerValidator with the given set of known issuers.
     *
     * @param knownIssuers the set of known/trusted issuer strings
     */
    public StandardIssuerValidator(Set<String> knownIssuers) {
        this.knownIssuers = Set.copyOf(knownIssuers);
    }

    /**
     * Validates the issuer against the known issuers set.
     *
     * @param issuer the iss claim value (may be null if absent)
     * @throws InvalidIssuerException if the issuer is null, blank, or not in the known set
     */
    @Override
    public void validate(String issuer) throws InvalidIssuerException {
        if (issuer == null || issuer.isBlank()) {
            throw new InvalidIssuerException("Token is missing the 'iss' claim");
        }
        if (!knownIssuers.contains(issuer)) {
            throw new InvalidIssuerException("Unknown issuer: '" + issuer + "'");
        }
        LOGGER.debug("Issuer {} validated successfully", issuer);
    }
}
