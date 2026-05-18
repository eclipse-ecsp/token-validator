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

import org.eclipse.ecsp.tokenvalidator.exception.MalformedTokenException;
import org.eclipse.ecsp.tokenvalidator.model.ParsedToken;

/**
 * Parses a JWT token and extracts header and payload data without signature verification.
 *
 * <p>The returned {@link ParsedToken} holds unverified data used internally to drive
 * key lookup and algorithm whitelist checks before the signature is verified.
 * Step 1 of the validation pipeline.
 *
 * @author Abhishek Kumar
 */
public interface TokenParser {

    /**
     * Parses the token and extracts kid, algorithm, issuer and raw claims.
     *
     * @param token the raw JWT string
     * @return ParsedToken containing unverified header and payload data
     * @throws MalformedTokenException if the token format is invalid
     */
    ParsedToken parse(String token) throws MalformedTokenException;
}
