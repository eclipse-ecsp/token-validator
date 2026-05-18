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

import org.eclipse.ecsp.tokenvalidator.AlgorithmValidator;
import org.eclipse.ecsp.tokenvalidator.exception.UnsupportedAlgorithmException;
import org.eclipse.ecsp.tokenvalidator.model.ParsedToken;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.util.List;
import java.util.Set;

/**
 * Algorithm validator that checks against a configured whitelist.
 *
 * <p>The {@code alg=none} algorithm is unconditionally denied before the whitelist
 * is consulted, regardless of configuration. Any other algorithm not present in the
 * whitelist also throws {@link UnsupportedAlgorithmException}.
 *
 * @author Abhishek Kumar
 */
public class WhitelistAlgorithmValidator implements AlgorithmValidator {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(WhitelistAlgorithmValidator.class);

    private static final String ALG_NONE = "none";

    private final Set<String> allowedAlgorithms;

    /**
     * Constructs a WhitelistAlgorithmValidator with the given list of allowed algorithms.
     *
     * @param allowedAlgorithms the list of allowed JWT algorithm names (case-sensitive)
     */
    public WhitelistAlgorithmValidator(List<String> allowedAlgorithms) {
        this.allowedAlgorithms = Set.copyOf(allowedAlgorithms);
    }

    /**
     * Validates the algorithm from the parsed token against the whitelist.
     *
     * @param parsedToken the unverified token data containing the algorithm header
     * @throws UnsupportedAlgorithmException if the algorithm is {@code none} or not whitelisted
     */
    @Override
    public void validate(ParsedToken parsedToken) throws UnsupportedAlgorithmException {
        String alg = parsedToken.getAlg();
        if (alg == null || ALG_NONE.equalsIgnoreCase(alg)) {
            throw new UnsupportedAlgorithmException(
                "Algorithm 'none' is unconditionally denied");
        }
        if (!allowedAlgorithms.contains(alg)) {
            throw new UnsupportedAlgorithmException(
                "Algorithm '" + alg + "' is not on the whitelist. Allowed: " + allowedAlgorithms);
        }
        LOGGER.debug("Algorithm {} validated successfully", alg);
    }
}
