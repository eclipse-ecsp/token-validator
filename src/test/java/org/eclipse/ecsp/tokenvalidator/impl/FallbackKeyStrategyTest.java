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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
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
    void defaultFallbackGlobalDefaultKeyInCacheIsFound() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generateKey();
        cache.put(DefaultFallbackKeyStrategy.GLOBAL_DEFAULT_KEY,
            new PublicKeyInfo(key, "default-kid", null, null));
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
    void defaultFallbackWithPemLoaderLoadsGlobalDefaultOnCacheMiss() throws Exception {
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
        // Key must be cached under the global default key
        assertTrue(cache.get(DefaultFallbackKeyStrategy.GLOBAL_DEFAULT_KEY).isPresent());
    }

    @Test
    void defaultFallbackWithPemLoaderUsesGlobalDefaultWhenIssuerDoesNotMatch() throws Exception {
        final InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generateKey();
        PemPublicKeyLoader pemLoader = mock(PemPublicKeyLoader.class);
        when(pemLoader.loadKeys(any(PublicKeySource.class))).thenReturn(Map.of("pemKid", key));

        // Source belongs to a different issuer but is marked as default
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("other-issuer");
        source.setLocation("/keys/pub.pem");
        source.setDefault(true);

        DefaultFallbackKeyStrategy strategy =
            new DefaultFallbackKeyStrategy(pemLoader, List.of(source));

        // Global default lookup should find the key even though issuer is "iss1"
        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "kid", cache);
        assertTrue(result.isPresent(), "Global default PEM source should be used when issuer does not match");
        assertNotNull(result.get().getPublicKey());
        // Global default should be cached
        assertTrue(cache.get(DefaultFallbackKeyStrategy.GLOBAL_DEFAULT_KEY).isPresent());
    }

    @Test
    void defaultFallbackReturnsEmptyWhenNoDefaultSourceExists() {
        final InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PemPublicKeyLoader pemLoader = mock(PemPublicKeyLoader.class);

        // Source exists but is NOT marked as default
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("iss1");
        source.setLocation("/keys/pub.pem");
        source.setDefault(false);

        DefaultFallbackKeyStrategy strategy =
            new DefaultFallbackKeyStrategy(pemLoader, List.of(source));

        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "kid", cache);
        assertFalse(result.isPresent(), "Should return empty when no source is marked as default");
    }

    @Test
    void defaultFallbackGlobalDefaultCacheHitSkipsPemLoad() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey cachedKey = generateKey();
        cache.put(DefaultFallbackKeyStrategy.GLOBAL_DEFAULT_KEY,
            new PublicKeyInfo(cachedKey, "global-kid", "any-issuer", null));

        PemPublicKeyLoader pemLoader = mock(PemPublicKeyLoader.class);
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("other-issuer");
        source.setLocation("/keys/pub.pem");
        source.setDefault(true);

        DefaultFallbackKeyStrategy strategy =
            new DefaultFallbackKeyStrategy(pemLoader, List.of(source));

        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "kid", cache);
        assertTrue(result.isPresent());
        verify(pemLoader, never()).loadKeys(any());
    }

    @Test
    void defaultFallbackJwksSourceNotEligibleForGlobalDefault() {
        final InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PemPublicKeyLoader pemLoader = mock(PemPublicKeyLoader.class);

        // JWKS source (url set, no location) marked as default — must NOT be used as global default
        PublicKeySource source = new PublicKeySource();
        source.setIssuer("other-issuer");
        source.setUrl("https://auth.example.com/.well-known/jwks.json");
        source.setDefault(true);
        // location is null → not a PEM source

        DefaultFallbackKeyStrategy strategy =
            new DefaultFallbackKeyStrategy(pemLoader, List.of(source));

        Optional<PublicKeyInfo> result = strategy.findFallback("iss1", "kid", cache);
        assertFalse(result.isPresent(), "JWKS sources must not be eligible as global default");
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

}

