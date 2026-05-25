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
import org.eclipse.ecsp.tokenvalidator.PublicKeyManager;
import org.eclipse.ecsp.tokenvalidator.PublicKeySourceProvider;
import org.eclipse.ecsp.tokenvalidator.exception.KeyLoadException;
import org.eclipse.ecsp.tokenvalidator.metrics.NoopValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.metrics.ValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyRotationEvent;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyType;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import org.springframework.context.event.EventListener;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Default implementation of {@link PublicKeyManager}.
 *
 * <p>Holds a copy-on-write {@link AtomicReference} of the key snapshot for lock-free reads.
 * Routes each {@link PublicKeySource} to the appropriate {@link PublicKeyLoader} by type.
 * Sanitizes {@code kid} values (max 512 chars, null bytes stripped) before cache lookup.
 * Listens for {@link PublicKeyRotationEvent} via {@code @EventListener} to trigger async refresh.
 *
 * @author Abhishek Kumar
 */
public class DefaultPublicKeyManager implements PublicKeyManager {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(DefaultPublicKeyManager.class);

    /** Maximum allowed length for a kid value before sanitization truncates it. */
    static final int MAX_KID_LENGTH = 512;

    private final List<PublicKeyLoader> loaders;
    private final List<PublicKeySourceProvider> sourceProviders;
    private final PublicKeyCache cache;
    private final FallbackKeyStrategy fallbackStrategy;
    private final boolean failOnStartupError;
    private final AtomicReference<List<PublicKeySource>> sourcesRef;
    private final ValidationMetricsRecorder metricsRecorder;
    private final ConcurrentHashMap<String, AtomicBoolean> refreshInProgress
        = new ConcurrentHashMap<>();

    /**
     * Constructs a DefaultPublicKeyManager with full configuration.
     *
     * @param loaders           the list of key loaders (JWKS, PEM, etc.)
     * @param sourceProviders   the list of source providers
     * @param cache             the public key cache
     * @param fallbackStrategy  the strategy for fallback key lookup on cache miss
     * @param failOnStartupError whether to throw on startup key load failure
     */
    public DefaultPublicKeyManager(
        List<PublicKeyLoader> loaders,
        List<PublicKeySourceProvider> sourceProviders,
        PublicKeyCache cache,
        FallbackKeyStrategy fallbackStrategy,
        boolean failOnStartupError) {
        this(loaders, sourceProviders, cache, fallbackStrategy, failOnStartupError,
            NoopValidationMetricsRecorder.INSTANCE);
    }

    /**
     * Constructs a DefaultPublicKeyManager with full configuration and a metrics recorder.
     *
     * @param loaders            the list of key loaders (JWKS, PEM, etc.)
     * @param sourceProviders    the list of source providers
     * @param cache              the public key cache
     * @param fallbackStrategy   the strategy for fallback key lookup on cache miss
     * @param failOnStartupError whether to throw on startup key load failure
     * @param metricsRecorder    the metrics recorder for observability
     */
    public DefaultPublicKeyManager(
        List<PublicKeyLoader> loaders,
        List<PublicKeySourceProvider> sourceProviders,
        PublicKeyCache cache,
        FallbackKeyStrategy fallbackStrategy,
        boolean failOnStartupError,
        ValidationMetricsRecorder metricsRecorder) {
        this.loaders = loaders;
        this.sourceProviders = sourceProviders;
        this.cache = cache;
        this.fallbackStrategy = fallbackStrategy;
        this.failOnStartupError = failOnStartupError;
        this.sourcesRef = new AtomicReference<>(List.of());
        this.metricsRecorder = metricsRecorder != null
            ? metricsRecorder : NoopValidationMetricsRecorder.INSTANCE;
    }

    /**
     * Finds a public key by key ID and issuer.
     *
     * <p>Sanitizes the kid value before cache lookup. Delegates to the fallback strategy
     * on cache miss.
     *
     * @param keyId  the key ID from the token header (may be null)
     * @param issuer the issuer from the token payload
     * @return Optional containing the PublicKeyInfo, or empty if not found
     */
    @Override
    public Optional<PublicKeyInfo> findPublicKey(String keyId, String issuer) {
        String sanitizedKid = sanitizeKid(keyId);
        if (sanitizedKid != null && !sanitizedKid.isBlank()) {
            String cacheKey = issuer + ":" + sanitizedKid;
            Optional<PublicKeyInfo> found = cache.get(cacheKey);
            if (found.isPresent()) {
                LOGGER.debug("Cache hit for issuer={} kid={}", issuer, sanitizedKid);
                metricsRecorder.recordCacheHit(issuer);
                return found;
            }
        }
        LOGGER.debug("Cache miss for issuer={} kid={}; triggering async refresh",
            issuer, sanitizedKid);
        metricsRecorder.recordCacheMiss(issuer);
        triggerAsyncRefreshForIssuer(issuer);
        return fallbackStrategy.findFallback(issuer, sanitizedKid, cache);
    }

    /**
     * Triggers an asynchronous per-issuer JWKS refresh on a cache miss, but only if
     * sources are configured for the issuer and no refresh is already in progress.
     *
     * @param issuer the issuer whose keys should be refreshed
     */
    private void triggerAsyncRefreshForIssuer(String issuer) {
        List<PublicKeySource> currentSources = sourcesRef.get();
        boolean hasSources = currentSources.stream()
            .anyMatch(src -> issuer.equals(src.getIssuer()));
        if (!hasSources) {
            LOGGER.debug("No sources configured for issuer={}; skipping async refresh", issuer);
            return;
        }
        AtomicBoolean inProgress = refreshInProgress.computeIfAbsent(
            issuer, k -> new AtomicBoolean(false));
        if (inProgress.compareAndSet(false, true)) {
            Thread.ofVirtual().start(() -> {
                try {
                    LOGGER.debug("Async background refresh started for issuer={}", issuer);
                    refreshPublicKeys(issuer);
                } catch (Exception ex) {
                    LOGGER.warn("Async background refresh failed for issuer={}: {}",
                        issuer, ex.getMessage());
                } finally {
                    inProgress.set(false);
                }
            });
        } else {
            LOGGER.debug("Async refresh already in progress for issuer={}; skipping", issuer);
        }
    }

    /**
     * Refreshes public keys from all configured sources.
     */
    @Override
    public void refreshPublicKeys() {
        List<PublicKeySource> sources = resolveAllSources();
        sourcesRef.set(sources);
        for (PublicKeySource source : sources) {
            refreshSource(source);
        }
        LOGGER.info("Public key refresh completed for all sources");
    }

    /**
     * Refreshes public keys for a specific issuer only.
     *
     * @param issuer the issuer whose keys should be refreshed
     */
    @Override
    public void refreshPublicKeys(String issuer) {
        if (issuer == null || issuer.isBlank()) {
            LOGGER.warn("refreshPublicKeys called with null/blank issuer; skipping");
            return;
        }
        List<PublicKeySource> sources = sourcesRef.get();
        if (sources.isEmpty()) {
            sources = resolveAllSources();
            sourcesRef.set(sources);
        }
        sources.stream()
            .filter(src -> issuer.equals(src.getIssuer()))
            .forEach(this::refreshSource);
        LOGGER.info("Public key refresh completed for issuer={}", issuer);
    }

    /**
     * Handles {@link PublicKeyRotationEvent} by triggering an async per-issuer refresh.
     *
     * @param event the rotation event containing the issuer that rotated keys
     */
    @EventListener
    public void onKeyRotation(PublicKeyRotationEvent event) {
        String issuer = event.getIssuer();
        LOGGER.info("Key rotation event received for issuer={}, triggering async refresh", issuer);
        Thread.ofVirtual().start(() -> refreshPublicKeys(issuer));
    }

    private List<PublicKeySource> resolveAllSources() {
        return sourceProviders.stream()
            .flatMap(provider -> provider.keySources().stream())
            .toList();
    }

    private void refreshSource(PublicKeySource source) {
        try {
            PublicKeyLoader loader = findLoader(source.getType());
            Map<String, PublicKey> keys = loader.loadKeys(source);
            populateCache(source, keys);
        } catch (Exception ex) {
            LOGGER.error("Failed to load keys for issuer={}: {}",
                source.getIssuer(), ex.getMessage());
            if (failOnStartupError) {
                throw new KeyLoadException(
                    "Key load failed for issuer: " + source.getIssuer(), ex);
            }
        }
    }

    private PublicKeyLoader findLoader(PublicKeyType type) {
        return loaders.stream()
            .filter(loader -> loader.getType() == type)
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("No loader found for type: " + type));
    }

    private void populateCache(PublicKeySource source, Map<String, PublicKey> keys) {
        String issuer = source.getIssuer();
        List<String> audiences = source.getAudiences();
        Map<String, PublicKeyInfo> newEntries = HashMap.newHashMap(keys.size());
        for (Map.Entry<String, PublicKey> entry : keys.entrySet()) {
            String kid = entry.getKey();
            PublicKeyInfo info = new PublicKeyInfo(entry.getValue(), kid, issuer, audiences);
            String cacheKey = issuer + ":" + kid;
            newEntries.put(cacheKey, info);
        }
        if (source.isDefault() && source.getType() == PublicKeyType.PEM && !keys.isEmpty()) {
            String defaultKeyId = keys.keySet().iterator().next();
            PublicKey defaultKey = keys.get(defaultKeyId);
            PublicKeyInfo defaultInfo = new PublicKeyInfo(defaultKey, defaultKeyId, issuer, audiences);
            newEntries.put(DefaultFallbackKeyStrategy.GLOBAL_DEFAULT_KEY, defaultInfo);
        }
        for (Map.Entry<String, PublicKeyInfo> entry : newEntries.entrySet()) {
            cache.put(entry.getKey(), entry.getValue());
        }
        LOGGER.info("Loaded {} keys for issuer={}", keys.size(), issuer);
    }

    private String sanitizeKid(String kid) {
        if (kid == null) {
            return null;
        }
        String sanitized = kid.replace("\0", "");
        if (sanitized.length() > MAX_KID_LENGTH) {
            sanitized = sanitized.substring(0, MAX_KID_LENGTH);
        }
        return sanitized;
    }

    /**
     * Returns the public key cache used by this manager.
     *
     * @return the public key cache
     */
    public PublicKeyCache getCache() {
        return cache;
    }
}
