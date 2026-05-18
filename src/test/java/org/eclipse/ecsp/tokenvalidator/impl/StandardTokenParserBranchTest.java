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

import org.eclipse.ecsp.tokenvalidator.exception.MalformedTokenException;
import org.eclipse.ecsp.tokenvalidator.model.ParsedToken;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Additional branch coverage for {@link StandardTokenParser}.
 *
 * @author Abhishek Kumar
 */
class StandardTokenParserBranchTest {

    private static final int RSA_KEY_SIZE = 2048;
    private static final long FUTURE_EXPIRY_MS = 60000L;

    private final StandardTokenParser parser = new StandardTokenParser();

    @Test
    void randomStringThrowsMalformed() {
        assertThrows(MalformedTokenException.class,
            () -> parser.parse("not.a.valid.jwt.thing.ok"));
    }

    @Test
    void tokenWithNoKidReturnsNullKid() throws Exception {
        // Build a JWT without kid header
        java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        java.security.KeyPair kp = gen.generateKeyPair();
        com.nimbusds.jose.JWSHeader header = new com.nimbusds.jose.JWSHeader
            .Builder(com.nimbusds.jose.JWSAlgorithm.RS256).build(); // no kid
        com.nimbusds.jwt.JWTClaimsSet claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
            .issuer("iss1")
            .expirationTime(new java.util.Date(System.currentTimeMillis() + FUTURE_EXPIRY_MS))
            .build();
        com.nimbusds.jwt.SignedJWT jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
        jwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(
            (java.security.interfaces.RSAPrivateKey) kp.getPrivate()));

        ParsedToken parsed = parser.parse(jwt.serialize());
        assertNull(parsed.getKid());
        assertNotNull(parsed.getAlg());
    }
}
