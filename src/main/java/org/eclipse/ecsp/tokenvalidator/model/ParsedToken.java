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

package org.eclipse.ecsp.tokenvalidator.model;

import java.util.Map;

/**
 * Unverified header and payload data extracted by the token parser before signature verification.
 *
 * <p>Contains the JWT header fields ({@code kid}, {@code alg}) and payload fields
 * ({@code iss}, {@code rawClaims}) extracted without verifying the signature.
 * This data is used internally to drive key lookup and algorithm validation only;
 * it must never be treated as trusted data.
 *
 * @author Abhishek Kumar
 */
public class ParsedToken {

    private final String kid;
    private final String alg;
    private final String iss;
    private final Map<String, Object> rawClaims;

    /**
     * Constructs a ParsedToken with the given header and payload fields.
     *
     * @param kid       the key ID from the JWT header (may be null)
     * @param alg       the algorithm from the JWT header
     * @param iss       the issuer from the JWT payload (may be null)
     * @param rawClaims the raw unverified payload claims
     */
    public ParsedToken(String kid, String alg, String iss, Map<String, Object> rawClaims) {
        this.kid = kid;
        this.alg = alg;
        this.iss = iss;
        this.rawClaims = rawClaims;
    }

    /**
     * Returns the key ID from the JWT header.
     *
     * @return the key ID, or null if not present
     */
    public String getKid() {
        return kid;
    }

    /**
     * Returns the algorithm from the JWT header.
     *
     * @return the algorithm string (e.g. "RS256")
     */
    public String getAlg() {
        return alg;
    }

    /**
     * Returns the issuer from the JWT payload.
     *
     * @return the issuer string, or null if not present
     */
    public String getIss() {
        return iss;
    }

    /**
     * Returns the raw unverified payload claims.
     *
     * @return map of claim names to raw values
     */
    public Map<String, Object> getRawClaims() {
        return rawClaims;
    }
}
