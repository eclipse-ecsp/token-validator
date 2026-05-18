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

import org.eclipse.ecsp.tokenvalidator.exception.InvalidTokenException;

/**
 * Normalizes raw token input before it is passed to the parsing step.
 *
 * <p>Allows callers to pass Bearer-prefixed values or other raw formats directly.
 * Step 0 of the validation pipeline.
 *
 * @author Abhishek Kumar
 */
public interface TokenPreprocessor {

    /**
     * Preprocesses the raw input and returns a clean JWT string.
     *
     * @param rawInput the raw token input (may include "Bearer " prefix, whitespace, etc.)
     * @return the normalised JWT string
     * @throws InvalidTokenException if the input cannot be normalised to a valid JWT format
     */
    String preprocess(String rawInput) throws InvalidTokenException;
}
