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

import com.nimbusds.jose.jwk.RSAKey;
import com.sun.net.httpserver.HttpServer;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyType;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration tests for {@link JwksPublicKeyLoader} using JDK HttpServer.
 *
 * @author Abhishek Kumar
 */
@SuppressWarnings("restriction")
class JwksPublicKeyLoaderTest {

    private static final int RSA_KEY_SIZE = 2048;
    private static final int HTTP_OK = 200;
    private static final int HTTP_ERROR = 500;
    private static final int NO_CONTENT_LENGTH = -1;
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

    private String generateJwksJson(String kid) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        KeyPair kp = gen.generateKeyPair();
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
            .keyID(kid)
            .build();
        return "{\"keys\":[" + rsaKey.toJSONString() + "]}";
    }

    @Test
    void loadsKeysFromJwksEndpoint() throws Exception {
        String jwksJson = generateJwksJson("kid1");
        server.createContext("/jwks", exchange -> {
            byte[] body = jwksJson.getBytes();
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(HTTP_OK, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });

        JwksPublicKeyLoader loader = new JwksPublicKeyLoader(
            new ExponentialBackoffJwksRetryStrategy(Duration.ofMillis(BASE_DELAY_MS), MAX_RETRY_ATTEMPTS));
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setUrl("http://localhost:" + port + "/jwks");

        Map<String, PublicKey> keys = loader.loadKeys(source);
        assertFalse(keys.isEmpty());
        assertTrue(keys.containsKey("kid1"));
        loader.close();
    }

    @Test
    void retriesOnServerErrorThenThrows() throws Exception {
        server.createContext("/error-jwks", exchange -> {
            exchange.sendResponseHeaders(HTTP_ERROR, NO_CONTENT_LENGTH);
            exchange.close();
        });

        JwksPublicKeyLoader loader = new JwksPublicKeyLoader(
            new ExponentialBackoffJwksRetryStrategy(Duration.ofMillis(BASE_DELAY_MS), MAX_RETRY_ATTEMPTS));
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setUrl("http://localhost:" + port + "/error-jwks");

        assertThrows(Exception.class, () -> loader.loadKeys(source));
        loader.close();
    }

    @Test
    void getTypeIsJwks() {
        JwksPublicKeyLoader loader = new JwksPublicKeyLoader(
            new ExponentialBackoffJwksRetryStrategy());
        assertSame(PublicKeyType.JWKS, loader.getType());
    }

    @Test
    void nonLoopbackHttpUrlIsRejected() {
        JwksPublicKeyLoader loader = new JwksPublicKeyLoader(
            new ExponentialBackoffJwksRetryStrategy());
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setUrl("http://idp.external.example.com/jwks");

        assertThrows(Exception.class, () -> loader.loadKeys(source));
    }

    @Test
    void httpsUrlPassesEnforcement() throws Exception {
        String jwksJson = generateJwksJson("kid-https");
        server.createContext("/https-jwks", exchange -> {
            byte[] body = jwksJson.getBytes();
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(HTTP_OK, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });

        // localhost with http:// is exempt from enforcement
        JwksPublicKeyLoader loader = new JwksPublicKeyLoader(
            new ExponentialBackoffJwksRetryStrategy(Duration.ofMillis(BASE_DELAY_MS),
                MAX_RETRY_ATTEMPTS));
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setUrl("http://localhost:" + port + "/https-jwks");

        Map<String, PublicKey> keys = loader.loadKeys(source);
        assertFalse(keys.isEmpty());
        loader.close();
    }

    @Test
    void httpsSchemePassesEnforcementButConnectionFails() {
        JwksPublicKeyLoader loader = new JwksPublicKeyLoader(
            new ExponentialBackoffJwksRetryStrategy(Duration.ofMillis(BASE_DELAY_MS),
                MAX_RETRY_ATTEMPTS));
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        // https:// passes the security check but will fail to connect (port 1 = connection refused)
        source.setUrl("https://127.0.0.1:1/jwks");

        // Should throw KeyLoadException due to connection failure, NOT HTTPS rejection
        Exception ex = assertThrows(Exception.class, () -> loader.loadKeys(source));
        assertFalse(ex.getMessage().contains("must use HTTPS"));
    }
}

