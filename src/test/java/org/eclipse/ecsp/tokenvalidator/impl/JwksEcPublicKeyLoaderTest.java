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

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.sun.net.httpserver.HttpServer;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for EC key loading in {@link JwksPublicKeyLoader}.
 *
 * @author Abhishek Kumar
 */
class JwksEcPublicKeyLoaderTest {

    private static final int HTTP_OK = 200;
    private static final long BASE_DELAY_MS = 10L;
    private static final int MAX_RETRY_ATTEMPTS = 2;

    private HttpServer server;
    private int port;

    @BeforeEach
    void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress(0), 0);
        port = server.getAddress().getPort();
        server.start();
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void loadsEcKeyFromJwks() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = gen.generateKeyPair();
        ECKey ecKey = new ECKey.Builder(Curve.P_256, (ECPublicKey) kp.getPublic())
            .keyID("eckid1")
            .build();
        String jwksJson = "{\"keys\":[" + ecKey.toJSONString() + "]}";
        byte[] responseBytes = jwksJson.getBytes(StandardCharsets.UTF_8);

        server.createContext("/ec-jwks", exchange -> {
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(HTTP_OK, responseBytes.length);
            exchange.getResponseBody().write(responseBytes);
            exchange.close();
        });

        JwksPublicKeyLoader loader = new JwksPublicKeyLoader(
            new ExponentialBackoffJwksRetryStrategy(Duration.ofMillis(BASE_DELAY_MS), MAX_RETRY_ATTEMPTS));
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setUrl("http://localhost:" + port + "/ec-jwks");

        Map<String, PublicKey> keys = loader.loadKeys(source);
        assertFalse(keys.isEmpty());
        assertTrue(keys.containsKey("eckid1"));
        loader.close();
    }
}

