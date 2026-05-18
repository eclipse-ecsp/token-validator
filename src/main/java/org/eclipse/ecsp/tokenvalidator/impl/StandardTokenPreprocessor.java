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

import org.eclipse.ecsp.tokenvalidator.TokenPreprocessor;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidTokenException;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;

/**
 * Default implementation of {@link TokenPreprocessor}.
 *
 * <p>Strips the {@code Bearer } prefix (case-insensitive), trims surrounding whitespace,
 * and throws {@link InvalidTokenException} if the result is blank.
 *
 * @author Abhishek Kumar
 */
public class StandardTokenPreprocessor implements TokenPreprocessor {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(StandardTokenPreprocessor.class);

    private static final String BEARER_PREFIX = "bearer ";

    /**
     * Constructs a new StandardTokenPreprocessor.
     */
    public StandardTokenPreprocessor() {
        // No-args constructor for bean registration in the Spring application context
    }

    /**
     * Preprocesses the raw input by stripping the Bearer prefix and trimming whitespace.
     *
     * @param rawInput the raw token input (may include "Bearer " prefix, whitespace, etc.)
     * @return the normalised JWT string
     * @throws InvalidTokenException if the input is null, blank, or reduces to blank after stripping
     */
    @Override
    public String preprocess(String rawInput) throws InvalidTokenException {
        if (rawInput == null || rawInput.isBlank()) {
            throw new InvalidTokenException("Token input is null or blank");
        }
        String trimmed = rawInput.trim();
        if (trimmed.toLowerCase().startsWith(BEARER_PREFIX)) {
            trimmed = trimmed.substring(BEARER_PREFIX.length()).trim();
        }
        if (trimmed.isBlank()) {
            throw new InvalidTokenException("Token input is empty after stripping Bearer prefix");
        }
        LOGGER.debug("Token preprocessed successfully");
        return trimmed;
    }
}
