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

import org.eclipse.ecsp.tokenvalidator.JwtTestUtil;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidSignatureException;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link NimbusTokenSignatureValidator}.
 *
 * @author Abhishek Kumar
 */
class NimbusTokenSignatureValidatorTest {

    private static final long TOKEN_LIFETIME_SECONDS = 3600L;

    private static KeyPair keyPair;
    private static KeyPair differentKeyPair;
    private final NimbusTokenSignatureValidator validator = new NimbusTokenSignatureValidator();

    @BeforeAll
    static void setUp() {
        keyPair = JwtTestUtil.generateRsaKeyPair();
        differentKeyPair = JwtTestUtil.generateRsaKeyPair();
    }

    @Test
    void validateValidSignatureReturnsClaimsPayload() throws Exception {
        String jwt = JwtTestUtil.createSignedJwt(
            "kid1", "https://issuer.example.com", "user1", TOKEN_LIFETIME_SECONDS, keyPair.getPrivate());
        List<TokenClaim> claims = validator.validate(jwt, keyPair.getPublic());
        assertFalse(claims.isEmpty());
    }

    @Test
    void validateContainsIssuerClaim() throws Exception {
        String jwt = JwtTestUtil.createSignedJwt(
            "kid1", "https://issuer.example.com", "user1", TOKEN_LIFETIME_SECONDS, keyPair.getPrivate());
        List<TokenClaim> claims = validator.validate(jwt, keyPair.getPublic());
        boolean hasIss = claims.stream().anyMatch(c -> "iss".equals(c.getName()));
        assertFalse(!hasIss);
    }

    @Test
    void validateWrongKeyThrows() {
        String jwt = JwtTestUtil.createSignedJwt(
            "kid1", "https://issuer.example.com", "user1", TOKEN_LIFETIME_SECONDS, keyPair.getPrivate());
        java.security.PublicKey wrongKey = differentKeyPair.getPublic();
        assertThrows(InvalidSignatureException.class,
            () -> validator.validate(jwt, wrongKey));
    }

    @Test
    void validateMalformedTokenThrows() {
        assertThrows(Exception.class,
            () -> validator.validate("notajwt", keyPair.getPublic()));
    }
}
