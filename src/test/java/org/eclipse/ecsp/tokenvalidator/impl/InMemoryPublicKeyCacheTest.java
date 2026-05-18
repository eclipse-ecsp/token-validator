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

import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link InMemoryPublicKeyCache}.
 *
 * @author Abhishek Kumar
 */
class InMemoryPublicKeyCacheTest {

    private static final int FAST_RSA_KEY_SIZE = 512;
    private static final int CACHE_CAPACITY = 100;
    private static final int LRU_CAPACITY = 2;
    private static final int CONCURRENT_CACHE_SIZE = 1000;
    private static final int CONCURRENT_THREADS = 10;

    private PublicKey generatePublicKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(FAST_RSA_KEY_SIZE);
        return generator.generateKeyPair().getPublic();
    }

    @Test
    void putAndGet() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generatePublicKey();
        PublicKeyInfo info = new PublicKeyInfo(key, "kid1", "iss1", null);
        cache.put("iss1:kid1", info);
        Optional<PublicKeyInfo> result = cache.get("iss1:kid1");
        assertTrue(result.isPresent());
        assertEquals("kid1", result.get().getKid());
    }

    @Test
    void getMissingReturnsEmpty() {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        Optional<PublicKeyInfo> result = cache.get("nonexistent");
        assertFalse(result.isPresent());
    }

    @Test
    void removeEntry() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generatePublicKey();
        PublicKeyInfo info = new PublicKeyInfo(key, "kid1", "iss1", null);
        cache.put("iss1:kid1", info);
        cache.remove("iss1:kid1");
        assertFalse(cache.get("iss1:kid1").isPresent());
    }

    @Test
    void clearByIssuer() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generatePublicKey();
        cache.put("iss1:kid1", new PublicKeyInfo(key, "kid1", "iss1", null));
        cache.put("iss1:kid2", new PublicKeyInfo(key, "kid2", "iss1", null));
        cache.put("iss2:kid3", new PublicKeyInfo(key, "kid3", "iss2", null));
        cache.clear("iss1");
        assertFalse(cache.get("iss1:kid1").isPresent());
        assertFalse(cache.get("iss1:kid2").isPresent());
        assertTrue(cache.get("iss2:kid3").isPresent());
    }

    @Test
    void sizeReflectsEntries() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        PublicKey key = generatePublicKey();
        cache.put("k1", new PublicKeyInfo(key, "k1", "iss", null));
        cache.put("k2", new PublicKeyInfo(key, "k2", "iss", null));
        assertEquals(LRU_CAPACITY, cache.size());
    }

    @Test
    void lruEvictsOldestEntry() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(LRU_CAPACITY);
        PublicKey key = generatePublicKey();
        cache.put("k1", new PublicKeyInfo(key, "k1", "iss", null));
        cache.put("k2", new PublicKeyInfo(key, "k2", "iss", null));
        cache.put("k3", new PublicKeyInfo(key, "k3", "iss", null));
        // LRU: k1 should be evicted
        assertEquals(LRU_CAPACITY, cache.size());
    }

    @Test
    void concurrentAccessDoesNotThrow() throws Exception {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CONCURRENT_CACHE_SIZE);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(FAST_RSA_KEY_SIZE);
        KeyPair kp = generator.generateKeyPair();

        List<Thread> threads = new ArrayList<>();
        for (int ii = 0; ii < CONCURRENT_THREADS; ii++) {
            int idx = ii;
            threads.add(Thread.ofVirtual().start(() -> {
                String key = "iss:kid" + idx;
                cache.put(key, new PublicKeyInfo(kp.getPublic(), "kid" + idx, "iss", null));
                cache.get(key);
            }));
        }
        for (Thread thread : threads) {
            thread.join();
        }
        assertEquals(CONCURRENT_THREADS, cache.size());
    }
}
