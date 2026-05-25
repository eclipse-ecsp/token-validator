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
 * Default fallback key strategy that resolves to the single global default PEM key source.
 *
 * <p>When a named {@code kid} is not found in the cache, this strategy uses a two-step fallback:
 * <ol>
 *   <li>Check the cache for the global default PEM key ({@link #GLOBAL_DEFAULT_KEY}).</li>
 *   <li>If absent and a {@link PemPublicKeyLoader} is configured, load the key from the first
 *       {@link org.eclipse.ecsp.tokenvalidator.model.PublicKeySource} whose
 *       {@code isDefault()} flag is {@code true} and whose {@code location} is non-null
 *       (file-system PEM source), regardless of the token's issuer claim.</li>
 * </ol>
 *
 * <p>Only one PEM source may be marked as default across all configured sources.
 * JWKS URL sources ({@code url} set, {@code location} absent) are never eligible.
 * If no default is found, {@link Optional#empty()} is returned and the caller
 * (typically {@link org.eclipse.ecsp.tokenvalidator.impl.DefaultPublicKeyManager})
 * will raise a {@link org.eclipse.ecsp.tokenvalidator.exception.KeyNotFoundException}.
 *
 * @author Abhishek Kumar
 */
public class DefaultFallbackKeyStrategy implements FallbackKeyStrategy {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(DefaultFallbackKeyStrategy.class);

    /**
     * Cache key used for the single global default PEM key that applies to any token issuer.
     *
     * <p>This entry is populated either at startup (via
     * {@link org.eclipse.ecsp.tokenvalidator.impl.DefaultPublicKeyManager}) or on the first
     * fallback load, so subsequent requests avoid redundant file-system reads.
     */
    public static final String GLOBAL_DEFAULT_KEY = "global:default";

    private final PemPublicKeyLoader pemLoader;
    private final List<PublicKeySource> sources;

    /**
     * Constructs a new DefaultFallbackKeyStrategy without a PEM loader.
     *
     * <p>Only the global default-key cache entry is consulted on fallback.
     */
    public DefaultFallbackKeyStrategy() {
        this(null, List.of());
    }

    /**
     * Constructs a DefaultFallbackKeyStrategy with an optional PEM loader and source list.
     *
     * <p>When {@code pemLoader} is non-null and the global default-key cache entry is absent,
     * this strategy attempts to load the single default PEM key from the file system before
     * returning {@link Optional#empty()}.
     *
     * @param pemLoader the PEM public key loader (may be null to disable file-system fallback)
     * @param sources   the list of configured public key sources; only the first source where
     *                  {@code isDefault()} is {@code true} and {@code getLocation()} is non-null
     *                  is used as the global default
     */
    public DefaultFallbackKeyStrategy(PemPublicKeyLoader pemLoader, List<PublicKeySource> sources) {
        this.pemLoader = pemLoader;
        this.sources = sources != null ? List.copyOf(sources) : List.of();
    }

    /**
     * Attempts to find the global default PEM key when the primary kid-based lookup fails.
     *
     * <ol>
     *   <li>Cache lookup for {@link #GLOBAL_DEFAULT_KEY}.</li>
     *   <li>If absent and a PEM loader is configured, load from the single default PEM source.</li>
     * </ol>
     *
     * @param issuer the token issuer
     * @param kid    the key ID that was not found (may be null)
     * @param cache  the public key cache to query for the global default key
     * @return Optional containing the global default key, or empty if none is configured
     */
    @Override
    public Optional<PublicKeyInfo> findFallback(String issuer, String kid, PublicKeyCache cache) {
        Optional<PublicKeyInfo> globalCached = cache.get(GLOBAL_DEFAULT_KEY);
        if (globalCached.isPresent()) {
            LOGGER.warn("Using global default PEM fallback key for issuer={} kid={}", issuer, kid);
            return globalCached;
        }
        if (pemLoader != null) {
            return loadFromAnyDefaultPem(kid, cache);
        }
        LOGGER.debug("No global default PEM key configured; fallback unavailable for issuer={}",
            issuer);
        return Optional.empty();
    }

    /**
     * Loads a key from the first default PEM source found, regardless of issuer.
     *
     * <p>Only sources where {@code isDefault()} is {@code true} and {@code getLocation()}
     * is non-null (file-system PEM) are eligible. The loaded key is cached under
     * {@link #GLOBAL_DEFAULT_KEY} for subsequent requests.
     *
     * @param kid   the key ID that was not found (used only for log messages)
     * @param cache the public key cache to populate on a successful load
     * @return Optional containing the loaded key, or empty if no eligible source exists
     *         or the load fails
     */
    private Optional<PublicKeyInfo> loadFromAnyDefaultPem(String kid, PublicKeyCache cache) {
        return sources.stream()
            .filter(src -> src.isDefault() && src.getLocation() != null)
            .findFirst()
            .flatMap(source -> {
                try {
                    Map<String, PublicKey> keys = pemLoader.loadKeys(source);
                    if (keys.isEmpty()) {
                        return Optional.empty();
                    }
                    String defaultKeyId = keys.keySet().iterator().next();
                    PublicKeyInfo info = new PublicKeyInfo(
                        keys.get(defaultKeyId), defaultKeyId, source.getIssuer(),
                        source.getAudiences());
                    cache.put(GLOBAL_DEFAULT_KEY, info);
                    LOGGER.warn("Loaded and cached global default PEM fallback key for kid={}",
                        kid);
                    return Optional.of(info);
                } catch (Exception _) {
                    LOGGER.error("Failed to load global default PEM fallback key");
                    return Optional.empty();
                }
            });
    }
}
