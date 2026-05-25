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
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Default fallback key strategy that checks the per-issuer default-key index in cache.
 *
 * <p>When a named {@code kid} is not found, this strategy attempts to find a default key
 * for the issuer in the cache (using the {@code issuer:default} composite key).
 * If no default key is present, {@link Optional#empty()} is returned and the caller
 * (typically {@link org.eclipse.ecsp.tokenvalidator.impl.DefaultPublicKeyManager})
 * will raise a {@link org.eclipse.ecsp.tokenvalidator.exception.KeyNotFoundException}.
 *
 * @author Abhishek Kumar
 */
public class DefaultFallbackKeyStrategy implements FallbackKeyStrategy {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(DefaultFallbackKeyStrategy.class);

    /** Cache key suffix for the default key entry per issuer. */
    public static final String DEFAULT_KEY_SUFFIX = "default";

    private final PemPublicKeyLoader pemLoader;
    private final List<PublicKeySource> sources;

    /**
     * Constructs a new DefaultFallbackKeyStrategy without a PEM loader.
     *
     * <p>Only the in-memory default-key cache index is consulted on fallback.
     */
    public DefaultFallbackKeyStrategy() {
        this(null, List.of());
    }

    /**
     * Constructs a DefaultFallbackKeyStrategy with an optional PEM loader and source list.
     *
     * <p>When {@code pemLoader} is non-null and the per-issuer default-key cache entry is absent,
     * this strategy attempts to load the default PEM key from the file system before returning
     * {@link Optional#empty()}.
     *
     * @param pemLoader the PEM public key loader (may be null to disable file-system fallback)
     * @param sources   the list of configured public key sources used to locate the PEM file path;
     *                  only sources where {@code isDefault()} is {@code true} are considered
     */
    public DefaultFallbackKeyStrategy(PemPublicKeyLoader pemLoader, List<PublicKeySource> sources) {
        this.pemLoader = pemLoader;
        this.sources = sources != null ? List.copyOf(sources) : List.of();
    }

    /**
     * Attempts to find a fallback key from the cache's default-key index.
     *
     * @param issuer the token issuer
     * @param kid    the key ID that was not found (may be null)
     * @param cache  the public key cache to query for fallback candidates
     * @return Optional containing a fallback key, or empty if no fallback is available
     */
    @Override
    public Optional<PublicKeyInfo> findFallback(String issuer, String kid, PublicKeyCache cache) {
        String defaultKey = issuer + ":" + DEFAULT_KEY_SUFFIX;
        Optional<PublicKeyInfo> cached = cache.get(defaultKey);
        if (cached.isPresent()) {
            LOGGER.warn("Using default fallback key for issuer={} kid={}", issuer, kid);
            return cached;
        }
        if (pemLoader != null) {
            return loadFromPem(issuer, kid, cache);
        }
        LOGGER.debug("No fallback key found in cache for issuer={}", issuer);
        return Optional.empty();
    }

    private Optional<PublicKeyInfo> loadFromPem(String issuer, String kid, PublicKeyCache cache) {
        return sources.stream()
            .filter(src -> issuer.equals(src.getIssuer())
                && src.isDefault()
                && src.getLocation() != null)
            .findFirst()
            .flatMap(source -> {
                try {
                    Map<String, PublicKey> keys = pemLoader.loadKeys(source);
                    if (keys.isEmpty()) {
                        return Optional.empty();
                    }
                    String defaultKeyId = keys.keySet().iterator().next();
                    PublicKeyInfo info = new PublicKeyInfo(
                        keys.get(defaultKeyId), defaultKeyId, issuer, source.getAudiences());
                    cache.put(issuer + ":" + DEFAULT_KEY_SUFFIX, info);
                    LOGGER.warn("Loaded and cached PEM fallback key for issuer={} kid={}",
                        issuer, kid);
                    return Optional.of(info);
                } catch (Exception _) {
                    LOGGER.error(
                        "Failed to load PEM fallback key for issuer={}",
                        issuer);
                    return Optional.empty();
                }
            });
    }
}
