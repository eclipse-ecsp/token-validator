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

import java.security.PublicKey;

/**
 * Resolved public key and its metadata, stored in {@code PublicKeyCache}.
 *
 * <p>Treated as effectively immutable once constructed. Fields are populated
 * from the corresponding {@link PublicKeySource} at key-load time.
 *
 * @author Abhishek Kumar
 */
public class PublicKeyInfo {

    private final PublicKey publicKey;
    private final String kid;
    private final String issuer;
    private final String expectedAudience;

    /**
     * Constructs a PublicKeyInfo with all required fields.
     *
     * @param publicKey        the resolved public key
     * @param kid              the key ID
     * @param issuer           the issuer this key belongs to
     * @param expectedAudience the expected audience for this issuer, or null to skip aud validation
     */
    public PublicKeyInfo(PublicKey publicKey, String kid, String issuer, String expectedAudience) {
        this.publicKey = publicKey;
        this.kid = kid;
        this.issuer = issuer;
        this.expectedAudience = expectedAudience;
    }

    /**
     * Returns the resolved public key.
     *
     * @return the public key
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Returns the key ID.
     *
     * @return the key ID
     */
    public String getKid() {
        return kid;
    }

    /**
     * Returns the issuer this key belongs to.
     *
     * @return the issuer string
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Returns the expected audience for this issuer.
     *
     * @return the expected audience string, or null if audience validation is not configured
     */
    public String getExpectedAudience() {
        return expectedAudience;
    }
}
