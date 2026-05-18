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

import org.eclipse.ecsp.tokenvalidator.exception.InvalidSignatureException;
import org.eclipse.ecsp.tokenvalidator.exception.MalformedTokenException;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import java.security.PublicKey;
import java.util.List;

/**
 * Verifies the cryptographic signature of a JWT token using the supplied public key.
 *
 * <p>The implementation must not enforce expiration during signature verification;
 * exp enforcement is performed exclusively by {@code TokenClaimsValidator}, ensuring
 * a single authoritative expiry check and avoiding double-validation.
 * Step 4 of the validation pipeline.
 *
 * @author Abhishek Kumar
 */
public interface TokenSignatureValidator {

    /**
     * Verifies the JWT signature and returns verified claims.
     *
     * @param token     the raw JWT string
     * @param publicKey the public key to verify against
     * @return list of verified claims extracted from the token
     * @throws InvalidSignatureException if signature verification fails
     * @throws MalformedTokenException   if the token format is invalid
     */
    List<TokenClaim> validate(String token, PublicKey publicKey)
        throws InvalidSignatureException, MalformedTokenException;
}
