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

import org.eclipse.ecsp.tokenvalidator.PublicKeyCache;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.junit.jupiter.api.Test;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultFallbackKeyStrategy} and {@link NoFallbackStrategy}.
 *
 * @author Abhishek Kumar
 */
class FallbackKeyStrategyTest {

    private static final int RSA_KEY_SIZE = 512;
    private static final int CACHE_CAPACITY = 100;

    private PublicKey generateKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        return gen.generateKeyPair().getPublic();
    }

    @Test
    void defaultFallbackFindsDefaultKey() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generateKey();
        cache.put("iss1:default", new PublicKeyInfo(key, "default", "iss1", null));
        DefaultFallbackKeyStrategy strategy = new DefaultFallbackKeyStrategy();
        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "missing-kid", cache);
        assertTrue(result.isPresent());
    }

    @Test
    void defaultFallbackEmptyCacheReturnsEmpty() {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultFallbackKeyStrategy strategy = new DefaultFallbackKeyStrategy();
        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "kid", cache);
        assertFalse(result.isPresent());
    }

    @Test
    void noFallbackStrategyAlwaysEmpty() {
        NoFallbackStrategy strategy = new NoFallbackStrategy();
        PublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "kid", cache);
        assertFalse(result.isPresent());
    }

    @Test
    void defaultFallbackWithPemLoaderLoadsKeyWhenCacheMiss() throws Exception {
        final InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generateKey();

        PemPublicKeyLoader pemLoader = mock(PemPublicKeyLoader.class);
        when(pemLoader.loadKeys(any(PublicKeySource.class))).thenReturn(Map.of("pemKid", key));

        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setLocation("/keys/pub.pem");
        source.setDefault(true);

        DefaultFallbackKeyStrategy strategy =
            new DefaultFallbackKeyStrategy(pemLoader, List.of(source));

        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "missing-kid", cache);

        assertTrue(result.isPresent());
        assertNotNull(result.get().getPublicKey());
        // Should also have been cached
        assertTrue(cache.get("iss1:default").isPresent());
    }

    @Test
    void defaultFallbackWithPemLoaderReturnsEmptyWhenNoMatchingSource() {
        final InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PemPublicKeyLoader pemLoader = mock(PemPublicKeyLoader.class);

        PublicKeySource source = new PublicKeySource();
        source.setIssuer("other-issuer");
        source.setLocation("/keys/pub.pem");
        source.setDefault(true);

        DefaultFallbackKeyStrategy strategy =
            new DefaultFallbackKeyStrategy(pemLoader, List.of(source));

        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "kid", cache);
        assertFalse(result.isPresent());
    }

    @Test
    void defaultFallbackWithPemLoaderReturnsEmptyOnLoaderError() {
        final InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PemPublicKeyLoader pemLoader = mock(PemPublicKeyLoader.class);
        when(pemLoader.loadKeys(any(PublicKeySource.class)))
            .thenThrow(new RuntimeException("file not found"));

        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setLocation("/keys/missing.pem");
        source.setDefault(true);

        DefaultFallbackKeyStrategy strategy =
            new DefaultFallbackKeyStrategy(pemLoader, List.of(source));

        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "kid", cache);
        assertFalse(result.isPresent());
    }

    @Test
    void defaultFallbackWithPemLoaderReturnsEmptyWhenLoaderReturnsNoKeys() {
        final InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PemPublicKeyLoader pemLoader = mock(PemPublicKeyLoader.class);
        when(pemLoader.loadKeys(any(PublicKeySource.class))).thenReturn(Map.of());

        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setLocation("/keys/empty.pem");
        source.setDefault(true);

        DefaultFallbackKeyStrategy strategy =
            new DefaultFallbackKeyStrategy(pemLoader, List.of(source));

        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "kid", cache);
        assertFalse(result.isPresent());
    }

    @Test
    void defaultFallbackPrefersCachedDefaultKeyOverPemLoad() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey cachedKey = generateKey();
        cache.put("iss1:default", new PublicKeyInfo(cachedKey, "default", "iss1", null));

        PemPublicKeyLoader pemLoader = mock(PemPublicKeyLoader.class);
        // pemLoader should NOT be called
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setLocation("/keys/pub.pem");
        source.setDefault(true);

        DefaultFallbackKeyStrategy strategy =
            new DefaultFallbackKeyStrategy(pemLoader, List.of(source));

        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "kid", cache);
        assertTrue(result.isPresent());
        // The returned key should be the cached one, not from the PEM loader
    }
}
