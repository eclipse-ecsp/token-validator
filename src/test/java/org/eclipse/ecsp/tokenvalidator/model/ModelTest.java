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

import org.junit.jupiter.api.Test;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for model value objects.
 *
 * @author Abhishek Kumar
 */
class ModelTest {

    private static final long EXP_TEST_VALUE = 12345L;

    @Test
    void tokenClaimGetName() {
        TokenClaim claim = new TokenClaim("sub", "user123");
        assertEquals("sub", claim.getName());
    }

    @Test
    void tokenClaimGetValue() {
        TokenClaim claim = new TokenClaim("exp", EXP_TEST_VALUE);
        assertEquals(EXP_TEST_VALUE, claim.getValue());
    }

    @Test
    void tokenClaimGetValueTyped() {
        TokenClaim claim = new TokenClaim("sub", "user123");
        String val = claim.getValue(String.class);
        assertEquals("user123", val);
    }

    @Test
    void tokenClaimGetValueTypedCastExceptionOnAssign() {
        TokenClaim claim = new TokenClaim("exp", EXP_TEST_VALUE);
        assertThrows(ClassCastException.class, () -> claim.getValue(String.class));
    }

    @Test
    void tokenClaimToString() {
        TokenClaim claim = new TokenClaim("iss", "issuer");
        String str = claim.toString();
        assertEquals("TokenClaim{name='iss'}", str);
    }

    @Test
    void parsedTokenFields() {
        Map<String, Object> rawClaims = Map.of("sub", "user1");
        ParsedToken token = new ParsedToken("kid1", "RS256", "issuer1", rawClaims);
        assertEquals("kid1", token.getKid());
        assertEquals("RS256", token.getAlg());
        assertEquals("issuer1", token.getIss());
        assertEquals(rawClaims, token.getRawClaims());
    }

    @Test
    void parsedTokenNullKid() {
        ParsedToken token = new ParsedToken(null, "RS256", "iss", Map.of());
        assertNull(token.getKid());
    }

    @Test
    void publicKeyTypeEnum() {
        assertEquals(PublicKeyType.JWKS, PublicKeyType.valueOf("JWKS"));
        assertEquals(PublicKeyType.PEM, PublicKeyType.valueOf("PEM"));
    }

    @Test
    void publicKeySourceGetters() {
        PublicKeySource source = new PublicKeySource();
        source.setId("id1");
        source.setIssuer("iss1");
        source.setUrl("https://example.com/jwks");
        source.setAudience("aud1");
        source.setDefault(true);
        assertEquals("id1", source.getId());
        assertEquals("iss1", source.getIssuer());
        assertEquals("https://example.com/jwks", source.getUrl());
        assertEquals("aud1", source.getAudience());
        assertEquals(PublicKeyType.JWKS, source.getType());
        assertEquals(true, source.isDefault());
    }

    @Test
    void publicKeySourcePemType() {
        PublicKeySource source = new PublicKeySource();
        source.setLocation("/path/to/key.pem");
        assertEquals(PublicKeyType.PEM, source.getType());
    }
}
