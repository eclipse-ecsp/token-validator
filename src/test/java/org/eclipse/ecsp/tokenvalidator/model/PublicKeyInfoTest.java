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
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Tests for {@link PublicKeyInfo}.
 *
 * @author Abhishek Kumar
 */
class PublicKeyInfoTest {

    private static final int RSA_KEY_SIZE = 512;

    private PublicKey generateKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        return gen.generateKeyPair().getPublic();
    }

    @Test
    void getPublicKey() throws Exception {
        PublicKey key = generateKey();
        PublicKeyInfo info = new PublicKeyInfo(key, "kid1", "iss1", List.of("aud1"));
        assertEquals(key, info.getPublicKey());
    }

    @Test
    void getKid() throws Exception {
        PublicKey key = generateKey();
        PublicKeyInfo info = new PublicKeyInfo(key, "kid1", "iss1", null);
        assertEquals("kid1", info.getKid());
    }

    @Test
    void getIssuer() throws Exception {
        PublicKey key = generateKey();
        PublicKeyInfo info = new PublicKeyInfo(key, "kid1", "iss1", null);
        assertEquals("iss1", info.getIssuer());
    }

    @Test
    void getExpectedAudience() throws Exception {
        PublicKey key = generateKey();
        PublicKeyInfo info = new PublicKeyInfo(key, "kid1", "iss1", List.of("myapi"));
        assertEquals(List.of("myapi"), info.getExpectedAudiences());
    }

    @Test
    void nullExpectedAudience() throws Exception {
        PublicKey key = generateKey();
        PublicKeyInfo info = new PublicKeyInfo(key, "kid1", "iss1", null);
        assertNull(info.getExpectedAudiences());
    }

    @Test
    void allFieldsNotNull() throws Exception {
        PublicKey key = generateKey();
        PublicKeyInfo info = new PublicKeyInfo(key, "kid1", "iss1", List.of("aud1"));
        assertNotNull(info.getPublicKey());
        assertNotNull(info.getKid());
        assertNotNull(info.getIssuer());
        assertNotNull(info.getExpectedAudiences());
    }
}
