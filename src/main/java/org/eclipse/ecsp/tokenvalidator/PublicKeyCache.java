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

import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import java.util.Optional;

/**
 * Caching interface for public keys used in JWT validation.
 *
 * <p>Handles in-memory caching of public keys with bounded capacity and LRU eviction.
 *
 * @author Abhishek Kumar
 */
public interface PublicKeyCache {

    /**
     * Puts a public key into the cache.
     *
     * @param key   composite cache key (typically {@code issuer:kid})
     * @param value the public key info to cache
     */
    void put(String key, PublicKeyInfo value);

    /**
     * Gets a public key from the cache.
     *
     * @param key composite cache key
     * @return Optional containing the cached PublicKeyInfo, or empty if not found
     */
    Optional<PublicKeyInfo> get(String key);

    /**
     * Removes a public key from the cache.
     *
     * @param key composite cache key
     */
    void remove(String key);

    /**
     * Removes all cached keys for a given issuer.
     *
     * @param issuer the issuer whose keys should be evicted
     */
    void clear(String issuer);

    /**
     * Returns the current number of entries in the cache.
     *
     * @return the cache size
     */
    int size();
}
