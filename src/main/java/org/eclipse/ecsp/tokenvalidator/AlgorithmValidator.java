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

import org.eclipse.ecsp.tokenvalidator.exception.UnsupportedAlgorithmException;
import org.eclipse.ecsp.tokenvalidator.model.ParsedToken;

/**
 * Validates that the algorithm used in a JWT is acceptable.
 *
 * <p>Replaces the hardcoded {@code List<String>} check inside {@code DefaultTokenValidator},
 * enabling dynamic whitelists, per-issuer rules, or audit logging.
 * Step 2 of the validation pipeline.
 *
 * @author Abhishek Kumar
 */
public interface AlgorithmValidator {

    /**
     * Validates the algorithm extracted from the parsed token.
     *
     * @param parsedToken the unverified token data containing the algorithm header
     * @throws UnsupportedAlgorithmException if the algorithm is not acceptable
     */
    void validate(ParsedToken parsedToken) throws UnsupportedAlgorithmException;
}
