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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Additional tests for {@link PemPublicKeyLoader} covering EC key loading.
 *
 * @author Abhishek Kumar
 */
class PemEcPublicKeyLoaderTest {

    @TempDir
    Path tempDir;

    private Path writePem(PublicKey key) throws Exception {
        String encoded = Base64.getEncoder().encodeToString(key.getEncoded());
        String pem = "-----BEGIN PUBLIC KEY-----\n" + encoded + "\n-----END PUBLIC KEY-----";
        Path file = tempDir.resolve("ec.pem");
        Files.writeString(file, pem);
        return file;
    }

    @Test
    void loadsEcPublicKeyFromPem() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = gen.generateKeyPair();
        Path pemFile = writePem(kp.getPublic());

        PemPublicKeyLoader loader = new PemPublicKeyLoader();
        PublicKeySource source = new PublicKeySource();
        source.setId("eckey");
        source.setIssuer("iss1");
        source.setLocation(pemFile.toAbsolutePath().toString());

        Map<String, PublicKey> keys = loader.loadKeys(source);
        assertFalse(keys.isEmpty());
        assertTrue(keys.containsKey("eckey"));
    }
}
