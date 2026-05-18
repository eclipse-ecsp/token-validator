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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidSignatureException;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.util.Date;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for EC key path in {@link NimbusTokenSignatureValidator}.
 *
 * @author Abhishek Kumar
 */
class NimbusEcSignatureValidatorTest {

    private static final long TOKEN_LIFETIME_SECONDS = 3600L;
    private static final int EC_KEY_SIZE = 256;
    private static final int FAST_RSA_KEY_SIZE = 512;

    private static String createEcJwt(KeyPair kp, String kid) throws Exception {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(kid).build();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
            .issuer("iss1")
            .expirationTime(Date.from(Instant.now().plusSeconds(TOKEN_LIFETIME_SECONDS)))
            .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner((ECPrivateKey) kp.getPrivate()));
        return jwt.serialize();
    }

    @Test
    void validateEcSignaturePasses() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(EC_KEY_SIZE);
        KeyPair kp = gen.generateKeyPair();
        String jwt = createEcJwt(kp, "eckid");
        NimbusTokenSignatureValidator validator = new NimbusTokenSignatureValidator();
        assertFalse(validator.validate(jwt, kp.getPublic()).isEmpty());
    }

    @Test
    void validateEcWrongKeyThrows() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(EC_KEY_SIZE);
        KeyPair kp1 = gen.generateKeyPair();
        KeyPair kp2 = gen.generateKeyPair();
        String jwt = createEcJwt(kp1, "eckid");
        NimbusTokenSignatureValidator validator = new NimbusTokenSignatureValidator();
        java.security.PublicKey wrongKey = kp2.getPublic();
        assertThrows(InvalidSignatureException.class,
            () -> validator.validate(jwt, wrongKey));
    }

    @Test
    void validateUnsupportedKeyTypeThrows() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(FAST_RSA_KEY_SIZE);
        KeyPair kp = gen.generateKeyPair();
        // Create an EC JWT but use RSA key to verify — should fail
        KeyPairGenerator ecGen = KeyPairGenerator.getInstance("EC");
        ecGen.initialize(EC_KEY_SIZE);
        KeyPair ecKp = ecGen.generateKeyPair();
        String jwt = createEcJwt(ecKp, "kid");
        NimbusTokenSignatureValidator validator = new NimbusTokenSignatureValidator();
        assertThrows(Exception.class, () -> validator.validate(jwt, kp.getPublic()));
    }
}
