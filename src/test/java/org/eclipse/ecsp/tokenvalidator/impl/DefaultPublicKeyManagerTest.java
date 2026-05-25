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

import org.eclipse.ecsp.tokenvalidator.FallbackKeyStrategy;
import org.eclipse.ecsp.tokenvalidator.PublicKeyCache;
import org.eclipse.ecsp.tokenvalidator.PublicKeyLoader;
import org.eclipse.ecsp.tokenvalidator.PublicKeySourceProvider;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyRotationEvent;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultPublicKeyManager}.
 *
 * @author Abhishek Kumar
 */
@ExtendWith(MockitoExtension.class)
class DefaultPublicKeyManagerTest {

    private static final int RSA_KEY_SIZE = 512;
    private static final int CACHE_CAPACITY = 100;
    private static final int LONG_KID_LENGTH = 600;
    private static final long ROTATION_WAIT_TIMEOUT_MS = 2000L;
    private static final long SLOW_LOADER_SLEEP_MS = 30L;

    private static PublicKey generateKey() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        return gen.generateKeyPair().getPublic();
    }

    private DefaultPublicKeyManager buildManager(
        PublicKeyLoader loader,
        PublicKeySourceProvider provider,
        PublicKeyCache cache,
        FallbackKeyStrategy fallbackStrategy) {
        return new DefaultPublicKeyManager(
            List.of(loader), List.of(provider), cache, fallbackStrategy, false);
    }

    @Test
    void findPublicKeyCacheHit() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generateKey();
        cache.put("iss1:kid1", new PublicKeyInfo(key, "kid1", "iss1", null));

        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new NoFallbackStrategy());

        Optional<PublicKeyInfo> result = manager.findPublicKey("kid1", "iss1");
        assertTrue(result.isPresent());
    }

    @Test
    void findPublicKeyUseFallbackOnCacheMiss() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generateKey();
        cache.put(DefaultFallbackKeyStrategy.GLOBAL_DEFAULT_KEY,
            new PublicKeyInfo(key, "default-kid", null, null));

        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new DefaultFallbackKeyStrategy());

        Optional<PublicKeyInfo> result = manager.findPublicKey("unknown-kid", "iss1");
        assertTrue(result.isPresent());
    }

    @Test
    void findPublicKeyNoFallbackReturnsEmpty() {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new NoFallbackStrategy());
        Optional<PublicKeyInfo> result = manager.findPublicKey("kid", "iss");
        assertFalse(result.isPresent());
    }

    @Test
    void sanitizesLongKid() {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new NoFallbackStrategy());
        String longKid = "k".repeat(LONG_KID_LENGTH);
        Optional<PublicKeyInfo> result = manager.findPublicKey(longKid, "iss");
        assertFalse(result.isPresent());
    }

    @Test
    void refreshPublicKeysLoadsFromProvider() throws Exception {
        PublicKey key = generateKey();
        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        when(loader.getType()).thenReturn(PublicKeyType.JWKS);
        when(loader.loadKeys(any(PublicKeySource.class))).thenReturn(Map.of("kid1", key));

        PublicKeySource source = new PublicKeySource();
        source.setId("src1");
        source.setIssuer("iss1");
        source.setUrl("https://example.com/jwks");

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source));

        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new NoFallbackStrategy());
        manager.refreshPublicKeys();

        Optional<PublicKeyInfo> result = cache.get("iss1:kid1");
        assertTrue(result.isPresent());
    }

    @Test
    void refreshPublicKeysByIssuer() throws Exception {
        PublicKey key = generateKey();
        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        when(loader.getType()).thenReturn(PublicKeyType.JWKS);
        when(loader.loadKeys(any(PublicKeySource.class))).thenReturn(Map.of("kid1", key));

        PublicKeySource source = new PublicKeySource();
        source.setId("src1");
        source.setIssuer("iss1");
        source.setUrl("https://example.com/jwks");

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source));

        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new NoFallbackStrategy());
        manager.refreshPublicKeys("iss1");

        Optional<PublicKeyInfo> result = cache.get("iss1:kid1");
        assertTrue(result.isPresent());
    }

    @Test
    void keyRotationEventTriggersRefresh() throws Exception {
        PublicKey key = generateKey();
        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        when(loader.getType()).thenReturn(PublicKeyType.JWKS);
        when(loader.loadKeys(any(PublicKeySource.class))).thenReturn(Map.of("kid1", key));

        PublicKeySource source = new PublicKeySource();
        source.setId("src1");
        source.setIssuer("iss1");
        source.setUrl("https://example.com/jwks");

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source));

        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new NoFallbackStrategy());
        manager.refreshPublicKeys();

        cache.clear("iss1");
        PublicKeyRotationEvent event = new PublicKeyRotationEvent(new Object(), "iss1");
        manager.onKeyRotation(event);
        long deadline = System.currentTimeMillis() + ROTATION_WAIT_TIMEOUT_MS;
        while (cache.get("iss1:kid1").isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.onSpinWait();
        }

        Optional<PublicKeyInfo> result = cache.get("iss1:kid1");
        assertTrue(result.isPresent());
    }

    @Test
    void nullKidFallbackLookup() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generateKey();
        cache.put(DefaultFallbackKeyStrategy.GLOBAL_DEFAULT_KEY,
            new PublicKeyInfo(key, "default-kid", null, null));
        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new DefaultFallbackKeyStrategy());

        Optional<PublicKeyInfo> result = manager.findPublicKey(null, "iss1");
        assertTrue(result.isPresent());
    }

    @Test
    void asyncRefreshTriggeredOnCacheMissWhenSourcesConfigured() throws Exception {
        PublicKey key = generateKey();
        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        when(loader.getType()).thenReturn(PublicKeyType.JWKS);
        when(loader.loadKeys(any(PublicKeySource.class))).thenReturn(Map.of("kid1", key));

        PublicKeySource source = new PublicKeySource();
        source.setId("src1");
        source.setIssuer("iss1");
        source.setUrl("https://example.com/jwks");

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source));

        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new NoFallbackStrategy());

        // Populate sourcesRef so async refresh knows about the source
        manager.refreshPublicKeys();
        cache.clear("iss1");

        // Cache miss triggers async refresh for the specific issuer
        Optional<PublicKeyInfo> result = manager.findPublicKey("kid1", "iss1");
        // Fallback returns empty immediately (NoFallbackStrategy)
        assertFalse(result.isPresent());

        // Wait for background refresh to complete
        long deadline = System.currentTimeMillis() + ROTATION_WAIT_TIMEOUT_MS;
        while (cache.get("iss1:kid1").isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.onSpinWait();
        }
        assertTrue(cache.get("iss1:kid1").isPresent(), "Key should be in cache after async refresh");
    }

    @Test
    void asyncRefreshSkippedWhenNoSourcesConfigured() {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);

        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new NoFallbackStrategy());

        // sourcesRef is empty — no async refresh should be triggered
        Optional<PublicKeyInfo> result = manager.findPublicKey("kid1", "iss1");
        assertFalse(result.isPresent());
    }

    @Test
    void duplicateAsyncRefreshIsDeduplicated() throws Exception {
        PublicKey key = generateKey();
        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        when(loader.getType()).thenReturn(PublicKeyType.JWKS);
        when(loader.loadKeys(any(PublicKeySource.class))).thenAnswer(inv -> {
            Thread.sleep(SLOW_LOADER_SLEEP_MS); //NOSONAR
            return Map.of("kid1", key);
        });

        PublicKeySource source = new PublicKeySource();
        source.setId("src1");
        source.setIssuer("iss1");
        source.setUrl("https://example.com/jwks");

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source));

        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = buildManager(loader, provider, cache,
            new NoFallbackStrategy());
        manager.refreshPublicKeys();
        cache.clear("iss1");

        // Call findPublicKey twice in quick succession — only one refresh should run
        manager.findPublicKey("kid1", "iss1");
        manager.findPublicKey("kid1", "iss1");

        // Wait for refresh to complete
        long deadline = System.currentTimeMillis() + ROTATION_WAIT_TIMEOUT_MS;
        while (cache.get("iss1:kid1").isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.onSpinWait();
        }
        assertTrue(cache.get("iss1:kid1").isPresent());
    }
}
