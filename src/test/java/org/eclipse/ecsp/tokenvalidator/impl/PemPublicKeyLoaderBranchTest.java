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
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Additional branch coverage tests for {@link PemPublicKeyLoader}.
 *
 * @author Abhishek Kumar
 */
class PemPublicKeyLoaderBranchTest {

    @TempDir
    Path tempDir;

    @Test
    void blankLocationThrows() {
        PemPublicKeyLoader loader = new PemPublicKeyLoader();
        PublicKeySource source = new PublicKeySource();
        source.setLocation("  ");
        assertThrows(IllegalArgumentException.class, () -> loader.loadKeys(source));
    }

    @Test
    void nullLocationThrows() {
        PemPublicKeyLoader loader = new PemPublicKeyLoader();
        PublicKeySource source = new PublicKeySource();
        source.setLocation(null);
        assertThrows(IllegalArgumentException.class, () -> loader.loadKeys(source));
    }

    @Test
    void missingFileThrows() {
        PemPublicKeyLoader loader = new PemPublicKeyLoader();
        PublicKeySource source = new PublicKeySource();
        source.setLocation("/nonexistent/path/key.pem");
        assertThrows(RuntimeException.class, () -> loader.loadKeys(source));
    }

    @Test
    void invalidPemContentThrows() throws Exception {
        Path badFile = tempDir.resolve("bad.pem");
        Files.writeString(badFile, "-----BEGIN PUBLIC KEY-----\nnotvalidbase64!!!\n-----END PUBLIC KEY-----");
        PemPublicKeyLoader loader = new PemPublicKeyLoader();
        PublicKeySource source = new PublicKeySource();
        source.setLocation(badFile.toAbsolutePath().toString());
        assertThrows(RuntimeException.class, () -> loader.loadKeys(source));
    }
}
