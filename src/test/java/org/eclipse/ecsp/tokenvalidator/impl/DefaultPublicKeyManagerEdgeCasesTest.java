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
import org.eclipse.ecsp.tokenvalidator.PublicKeySourceProvider;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyType;
import org.junit.jupiter.api.Test;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Additional coverage tests for {@link DefaultPublicKeyManager} edge cases.
 *
 * @author Abhishek Kumar
 */
class DefaultPublicKeyManagerEdgeCasesTest {

    private static final int RSA_KEY_SIZE = 512;
    private static final int CACHE_CAPACITY = 100;

    @Test
    void failOnStartupErrorThrowsOnLoadFailure() {
        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        when(loader.getType()).thenReturn(PublicKeyType.JWKS);
        when(loader.loadKeys(any(PublicKeySource.class))).thenThrow(new RuntimeException("fetch failed"));

        PublicKeySource source = new PublicKeySource();
        source.setId("src1");
        source.setIssuer("iss1");
        source.setUrl("https://example.com/jwks");

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source));

        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = new DefaultPublicKeyManager(
            List.of(loader), List.of(provider), cache, new NoFallbackStrategy(), true);

        assertThrows(RuntimeException.class, manager::refreshPublicKeys);
    }

    @Test
    void refreshDefaultPemKeyIsStoredUnderGlobalDefaultKey() throws Exception {
        java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        PublicKey key = gen.generateKeyPair().getPublic();

        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        when(loader.getType()).thenReturn(PublicKeyType.PEM);
        when(loader.loadKeys(any(PublicKeySource.class))).thenReturn(Map.of("kid1", key));

        PublicKeySource source = new PublicKeySource();
        source.setId("src1");
        source.setIssuer("iss1");
        source.setLocation("/keys/pub.pem");
        source.setDefault(true);

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source));

        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = new DefaultPublicKeyManager(
            List.of(loader), List.of(provider), cache, new NoFallbackStrategy(), false);
        manager.refreshPublicKeys();

        // Default PEM key must be stored under the global default key
        java.util.Optional<org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo> defaultKey =
            cache.get(DefaultFallbackKeyStrategy.GLOBAL_DEFAULT_KEY);
        assertTrue(defaultKey.isPresent());
    }

    @Test
    void refreshJwksDefaultFlagDoesNotPopulateGlobalDefaultKey() throws Exception {
        java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        PublicKey key = gen.generateKeyPair().getPublic();

        PublicKeyLoader loader = mock(PublicKeyLoader.class);
        when(loader.getType()).thenReturn(PublicKeyType.JWKS);
        when(loader.loadKeys(any(PublicKeySource.class))).thenReturn(Map.of("kid1", key));

        // JWKS source marked default — must NOT populate global:default
        PublicKeySource source = new PublicKeySource();
        source.setId("src1");
        source.setIssuer("iss1");
        source.setUrl("https://example.com/jwks");
        source.setDefault(true);

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source));

        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = new DefaultPublicKeyManager(
            List.of(loader), List.of(provider), cache, new NoFallbackStrategy(), false);
        manager.refreshPublicKeys();

        assertFalse(cache.get(DefaultFallbackKeyStrategy.GLOBAL_DEFAULT_KEY).isPresent());
    }

    @Test
    void kidWithNullBytesIsSanitized() {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = new DefaultPublicKeyManager(
            List.of(), List.of(), cache, new NoFallbackStrategy(), false);
        // Kid with null byte — should be sanitized and not found
        java.util.Optional<org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo> result =
            manager.findPublicKey("kid\0evil", "iss");
        assertFalse(result.isPresent());
    }

    @Test
    void blankKidSkipsCacheAndUsesFallback() throws Exception {
        java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        PublicKey key = gen.generateKeyPair().getPublic();

        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put(DefaultFallbackKeyStrategy.GLOBAL_DEFAULT_KEY,
            new PublicKeyInfo(key, "default-kid", null, null));

        DefaultPublicKeyManager manager = new DefaultPublicKeyManager(
            List.of(), List.of(), cache, new DefaultFallbackKeyStrategy(), false);

        // Blank kid bypasses direct cache lookup, falls to global default fallback
        Optional<PublicKeyInfo> result = manager.findPublicKey("   ", "iss1");
        assertTrue(result.isPresent());
    }

    @Test
    void refreshPublicKeysNullIssuerIsIgnored() {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = new DefaultPublicKeyManager(
            List.of(), List.of(), cache, new NoFallbackStrategy(), false);
        assertDoesNotThrow(() -> manager.refreshPublicKeys(null));
    }

    @Test
    void refreshPublicKeysBlankIssuerIsIgnored() {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        DefaultPublicKeyManager manager = new DefaultPublicKeyManager(
            List.of(), List.of(), cache, new NoFallbackStrategy(), false);
        assertDoesNotThrow(() -> manager.refreshPublicKeys("  "));
    }

    @Test
    void refreshPublicKeysByIssuerLoadsSourcesWhenEmpty() throws Exception {
        java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        PublicKey key = gen.generateKeyPair().getPublic();

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
        DefaultPublicKeyManager manager = new DefaultPublicKeyManager(
            List.of(loader), List.of(provider), cache, new NoFallbackStrategy(), false);

        // Call with issuer directly (sourcesRef is empty, will be populated)
        manager.refreshPublicKeys("iss1");
        assertTrue(cache.get("iss1:kid1").isPresent());
    }
}
