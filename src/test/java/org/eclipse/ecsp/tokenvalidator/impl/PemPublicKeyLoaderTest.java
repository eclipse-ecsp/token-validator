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

import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link PemPublicKeyLoader}.
 *
 * @author Abhishek Kumar
 */
class PemPublicKeyLoaderTest {

    private static final int RSA_KEY_SIZE = 2048;

    @TempDir
    Path tempDir;

    private Path writePemFile(PublicKey publicKey) throws Exception {
        String encoded = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String pem = "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----";
        Path pemFile = tempDir.resolve("key.pem");
        Files.writeString(pemFile, pem);
        return pemFile;
    }

    @Test
    void loadsRsaPublicKeyFromPem() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        KeyPair kp = gen.generateKeyPair();
        Path pemFile = writePemFile(kp.getPublic());

        PemPublicKeyLoader loader = new PemPublicKeyLoader();
        PublicKeySource source = new PublicKeySource();
        source.setId("mykey");
        source.setIssuer("iss1");
        source.setLocation(pemFile.toAbsolutePath().toString());

        Map<String, PublicKey> keys = loader.loadKeys(source);
        assertFalse(keys.isEmpty());
        assertTrue(keys.containsKey("mykey"));
    }

    @Test
    void usesDefaultKeyIdWhenIdNotSet() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        KeyPair kp = gen.generateKeyPair();
        Path pemFile = writePemFile(kp.getPublic());

        PemPublicKeyLoader loader = new PemPublicKeyLoader();
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setLocation(pemFile.toAbsolutePath().toString());

        Map<String, PublicKey> keys = loader.loadKeys(source);
        assertTrue(keys.containsKey("default"));
    }

    @Test
    void invalidPathThrows() {
        PemPublicKeyLoader loader = new PemPublicKeyLoader();
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setLocation("/nonexistent/path/key.pem");
        assertThrows(Exception.class, () -> loader.loadKeys(source));
    }

    @Test
    void getTypeIsPem() {
        PemPublicKeyLoader loader = new PemPublicKeyLoader();
        assertSame(PublicKeyType.PEM, loader.getType());
    }

    @Test
    void closeIsIdempotent() {
        PemPublicKeyLoader loader = new PemPublicKeyLoader();
        assertDoesNotThrow(loader::close);
    }
}
