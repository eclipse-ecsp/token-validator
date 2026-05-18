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

import org.eclipse.ecsp.tokenvalidator.PublicKeyLoader;
import org.eclipse.ecsp.tokenvalidator.exception.KeyLoadException;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyType;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * Loads a public key from a PEM file on the file system.
 *
 * <p>Supports RSA and EC public keys in PEM format (PKCS#8 SubjectPublicKeyInfo).
 * The PEM file path is taken from {@link PublicKeySource#getLocation()}.
 *
 * @author Abhishek Kumar
 */
public class PemPublicKeyLoader implements PublicKeyLoader {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(PemPublicKeyLoader.class);

    private static final String PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
    private static final String PEM_FOOTER = "-----END PUBLIC KEY-----";

    /**
     * Constructs a new PemPublicKeyLoader.
     */
    public PemPublicKeyLoader() {
        // No-args constructor for bean registration in the Spring application context
    }

    /**
     * Loads public keys from the PEM file configured in the given source.
     *
     * @param config the public key source configuration containing the PEM file path
     * @return map of key ID (or "default") to public key
     * @throws RuntimeException if the PEM file cannot be read or parsed
     */
    @Override
    public Map<String, PublicKey> loadKeys(PublicKeySource config) {
        String location = config.getLocation();
        if (location == null || location.isBlank()) {
            throw new IllegalArgumentException("PEM key source has no location configured");
        }
        try {
            Path pemPath = Path.of(location);
            String pemContent = Files.readString(pemPath);
            PublicKey publicKey = parsePem(pemContent);
            String keyId = config.getId() != null ? config.getId() : "default";
            LOGGER.info("PEM key loaded successfully from location={}", location);
            return Map.of(keyId, publicKey);
        } catch (IOException ex) {
            throw new KeyLoadException("Failed to read PEM file: " + location, ex);
        } catch (Exception ex) {
            throw new KeyLoadException("Failed to parse PEM key from: " + location
                + " — " + ex.getMessage(), ex);
        }
    }

    private PublicKey parsePem(String pemContent) throws KeyLoadException {
        String cleaned = pemContent
            .replace(PEM_HEADER, "")
            .replace(PEM_FOOTER, "")
            .replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(cleaned);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return tryParseKey(spec);
    }

    private PublicKey tryParseKey(X509EncodedKeySpec spec) throws KeyLoadException {
        Exception rsaException;
        try {
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception rsaEx) {
            rsaException = rsaEx;
        }
        try {
            return KeyFactory.getInstance("EC").generatePublic(spec);
        } catch (Exception ecEx) {
            throw new KeyLoadException(
                "Key is neither a valid RSA nor EC public key. RSA error: "
                    + rsaException.getMessage() + "; EC error: " + ecEx.getMessage(), ecEx);
        }
    }

    /**
     * Returns the type of public key source this loader supports.
     *
     * @return {@link PublicKeyType#PEM}
     */
    @Override
    public PublicKeyType getType() {
        return PublicKeyType.PEM;
    }

    /**
     * Closes this loader (no resources to release for PEM loading).
     *
     * @throws IOException never thrown
     */
    @Override
    public void close() throws IOException {
        // No resources to close for PEM file loading
    }
}
