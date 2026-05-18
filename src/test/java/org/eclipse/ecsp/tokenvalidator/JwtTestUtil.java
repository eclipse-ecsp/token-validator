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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.time.Instant;
import java.util.Date;

/**
 * Utility for generating RSA key pairs and JWT tokens in tests.
 *
 * @author Abhishek Kumar
 */
public final class JwtTestUtil {

    private static final int RSA_KEY_SIZE = 2048;
    private static final long EXPIRED_SECONDS = -3600L;

    private JwtTestUtil() {
    }

    /**
     * Generates a new 2048-bit RSA key pair.
     *
     * @return the generated key pair
     */
    public static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(RSA_KEY_SIZE);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new RuntimeException("Failed to generate RSA key pair", ex);
        }
    }

    /**
     * Creates a signed JWT with RS256 using the given key pair.
     *
     * @param kid           the key ID to put in the header
     * @param issuer        the issuer claim
     * @param subject       the subject claim
     * @param audience      the audience claim (may be null)
     * @param expiresIn     seconds until expiry from now (negative for expired)
     * @param privateKey    the private key to sign with
     * @return the serialized JWT string
     */
    public static String createSignedJwt(
        String kid,
        String issuer,
        String subject,
        String audience,
        long expiresIn,
        PrivateKey privateKey) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(kid)
                .build();
            Instant now = Instant.now();
            JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .expirationTime(Date.from(now.plusSeconds(expiresIn)))
                .issueTime(Date.from(now));
            if (audience != null) {
                claimsBuilder.audience(audience);
            }
            SignedJWT jwt = new SignedJWT(header, claimsBuilder.build());
            jwt.sign(new RSASSASigner(privateKey));
            return jwt.serialize();
        } catch (Exception ex) {
            throw new RuntimeException("Failed to create JWT", ex);
        }
    }

    /**
     * Creates a signed JWT with RS256 using the given key pair.
     *
     * @param kid        the key ID
     * @param issuer     the issuer claim
     * @param subject    the subject claim
     * @param expiresIn  seconds until expiry (negative for already-expired)
     * @param privateKey the private key
     * @return the serialized JWT
     */
    public static String createSignedJwt(
        String kid, String issuer, String subject, long expiresIn, PrivateKey privateKey) {
        return createSignedJwt(kid, issuer, subject, null, expiresIn, privateKey);
    }

    /**
     * Creates an expired JWT token.
     *
     * @param kid        the key ID
     * @param issuer     the issuer
     * @param privateKey the private key
     * @return the serialized expired JWT
     */
    public static String createExpiredJwt(String kid, String issuer, PrivateKey privateKey) {
        return createSignedJwt(kid, issuer, "subject", EXPIRED_SECONDS, privateKey);
    }

    /**
     * Returns a fake 5-part JWE compact serialization string (for JWE detection tests).
     *
     * @return a 5-part dot-separated string resembling a compact JWE
     */
    public static String createFakeJweToken() {
        return "header.encryptedKey.iv.ciphertext.authTag";
    }
}
