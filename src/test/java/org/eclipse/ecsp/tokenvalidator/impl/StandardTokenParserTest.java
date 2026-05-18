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
import org.eclipse.ecsp.tokenvalidator.exception.MalformedTokenException;
import org.eclipse.ecsp.tokenvalidator.exception.UnsupportedTokenTypeException;
import org.eclipse.ecsp.tokenvalidator.model.ParsedToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link StandardTokenParser}.
 *
 * @author Abhishek Kumar
 */
class StandardTokenParserTest {

    private static final long TOKEN_LIFETIME_SECONDS = 3600L;

    private static KeyPair keyPair;
    private final StandardTokenParser parser = new StandardTokenParser();

    @BeforeAll
    static void setUp() {
        keyPair = JwtTestUtil.generateRsaKeyPair();
    }

    @Test
    void parseValidJwt() throws Exception {
        String jwt = JwtTestUtil.createSignedJwt("kid1", "https://issuer.example.com",
            "user1", TOKEN_LIFETIME_SECONDS, keyPair.getPrivate());
        ParsedToken token = parser.parse(jwt);
        assertEquals("kid1", token.getKid());
        assertEquals("RS256", token.getAlg());
        assertEquals("https://issuer.example.com", token.getIss());
    }

    @Test
    void parseJweThrows() {
        String jweToken = JwtTestUtil.createFakeJweToken();
        assertThrows(UnsupportedTokenTypeException.class, () -> parser.parse(jweToken));
    }

    @Test
    void parseMalformedThrows() {
        assertThrows(MalformedTokenException.class, () -> parser.parse("notajwt"));
    }

    @Test
    void parseEmptyThrows() {
        assertThrows(MalformedTokenException.class, () -> parser.parse(""));
    }
}
