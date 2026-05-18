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
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Bounded in-memory LRU cache for public keys.
 *
 * <p>Uses an {@link AtomicReference} holding an immutable snapshot for lock-free reads on the
 * hot validation path. Writes (put, remove, clear) are serialized through a dedicated write
 * lock and perform a copy-on-write: a new {@link LinkedHashMap} is built, updated, and then
 * atomically published. Eviction uses insertion-order LRU semantics — the oldest-inserted key
 * is removed when the cache exceeds {@code maxSize}.
 *
 * <p>Composite cache key is {@code issuer:kid}. The {@link #clear(String)} method removes
 * all entries whose key starts with the given issuer prefix.
 *
 * @author Abhishek Kumar
 */
public class InMemoryPublicKeyCache implements PublicKeyCache {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(InMemoryPublicKeyCache.class);

    /** Default maximum number of entries in the LRU cache. */
    public static final int DEFAULT_MAX_SIZE = 1000;

    private final int maxSize;
    private final Object writeLock = new Object();
    private final AtomicReference<Map<String, PublicKeyInfo>> snapshotRef;

    /**
     * Constructs an InMemoryPublicKeyCache with the default maximum size.
     */
    public InMemoryPublicKeyCache() {
        this(DEFAULT_MAX_SIZE);
    }

    /**
     * Constructs an InMemoryPublicKeyCache with the given maximum size.
     *
     * @param maxSize the maximum number of entries before LRU eviction occurs
     */
    public InMemoryPublicKeyCache(int maxSize) {
        this.maxSize = maxSize;
        this.snapshotRef = new AtomicReference<>(Collections.emptyMap());
    }

    /**
     * Puts a public key into the cache.
     *
     * <p>Performs a copy-on-write: copies the current snapshot, adds the entry,
     * evicts the oldest entry if the cache exceeds {@code maxSize}, and atomically
     * publishes the new snapshot.
     *
     * @param key   composite cache key (typically {@code issuer:kid})
     * @param value the public key info to cache
     */
    @Override
    public void put(String key, PublicKeyInfo value) {
        synchronized (writeLock) {
            LinkedHashMap<String, PublicKeyInfo> copy = new LinkedHashMap<>(snapshotRef.get());
            copy.put(key, value);
            Iterator<String> it = copy.keySet().iterator();
            while (copy.size() > maxSize && it.hasNext()) {
                it.next();
                it.remove();
            }
            snapshotRef.set(Collections.unmodifiableMap(copy));
            LOGGER.debug("Cached public key for key={}", key);
        }
    }

    /**
     * Gets a public key from the cache.
     *
     * <p>Lock-free: reads directly from the atomic snapshot without acquiring any lock.
     *
     * @param key composite cache key
     * @return Optional containing the cached PublicKeyInfo, or empty if not found
     */
    @Override
    public Optional<PublicKeyInfo> get(String key) {
        PublicKeyInfo info = snapshotRef.get().get(key);
        if (info != null) {
            LOGGER.debug("Cache hit for key={}", key);
        } else {
            LOGGER.debug("Cache miss for key={}", key);
        }
        return Optional.ofNullable(info);
    }

    /**
     * Removes a public key from the cache.
     *
     * @param key composite cache key
     */
    @Override
    public void remove(String key) {
        synchronized (writeLock) {
            Map<String, PublicKeyInfo> current = snapshotRef.get();
            if (current.containsKey(key)) {
                LinkedHashMap<String, PublicKeyInfo> copy = new LinkedHashMap<>(current);
                copy.remove(key);
                snapshotRef.set(Collections.unmodifiableMap(copy));
            }
            LOGGER.debug("Removed cache entry for key={}", key);
        }
    }

    /**
     * Removes all cached keys whose composite key starts with the given issuer prefix.
     *
     * @param issuer the issuer whose keys should be evicted
     */
    @Override
    public void clear(String issuer) {
        synchronized (writeLock) {
            String prefix = issuer + ":";
            LinkedHashMap<String, PublicKeyInfo> copy = new LinkedHashMap<>(snapshotRef.get());
            copy.keySet().removeIf(k -> k.startsWith(prefix));
            snapshotRef.set(Collections.unmodifiableMap(copy));
            LOGGER.debug("Cleared all cached keys for issuer={}", issuer);
        }
    }

    /**
     * Returns the current number of entries in the cache.
     *
     * @return the cache size
     */
    @Override
    public int size() {
        return snapshotRef.get().size();
    }

    /**
     * Returns the configured maximum size of this cache.
     *
     * @return the maximum number of entries
     */
    public int getMaxSize() {
        return maxSize;
    }
}
