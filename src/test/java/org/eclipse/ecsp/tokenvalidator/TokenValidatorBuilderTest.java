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

package org.eclipse.ecsp.tokenvalidator;

import org.eclipse.ecsp.tokenvalidator.impl.DefaultPublicKeyManager;
import org.eclipse.ecsp.tokenvalidator.impl.InMemoryPublicKeyCache;
import org.eclipse.ecsp.tokenvalidator.impl.NoFallbackStrategy;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for {@link TokenValidatorBuilder}.
 *
 * @author Abhishek Kumar
 */
class TokenValidatorBuilderTest {

    private static final int RSA_KEY_SIZE = 2048;
    private static final int CACHE_CAPACITY = 100;
    private static final long CLOCK_SKEW_SECONDS = 30L;

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        return gen.generateKeyPair();
    }

    private static PublicKeyManager buildKeyManager(InMemoryPublicKeyCache cache) {
        return new DefaultPublicKeyManager(List.of(), List.of(), cache, new NoFallbackStrategy(), false);
    }

    @Test
    void buildWithDefaultsProducesValidator() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("https://iss.example.com:kid1",
            new PublicKeyInfo(kp.getPublic(), "kid1", "https://iss.example.com", null));
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildKeyManager(cache))
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithCustomWhitelistedAlgorithms() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("https://iss.example.com:kid1",
            new PublicKeyInfo(kp.getPublic(), "kid1", "https://iss.example.com", null));
        TokenValidator validator = TokenValidatorBuilder.builder()
            .whitelistedAlgorithms(List.of("RS256"))
            .publicKeyManager(buildKeyManager(cache))
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithClockSkew() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("https://iss.example.com:kid1",
            new PublicKeyInfo(kp.getPublic(), "kid1", "https://iss.example.com", null));
        TokenValidator validator = TokenValidatorBuilder.builder()
            .clockSkew(Duration.ofSeconds(CLOCK_SKEW_SECONDS))
            .publicKeyManager(buildKeyManager(cache))
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithCustomValidationHook() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("https://iss.example.com:kid1",
            new PublicKeyInfo(kp.getPublic(), "kid1", "https://iss.example.com", null));
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildKeyManager(cache))
            .customValidators(List.of())
            .build();
        assertNotNull(validator);
    }
}
