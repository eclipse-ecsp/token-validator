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

package org.eclipse.ecsp.tokenvalidator.config;

import org.eclipse.ecsp.tokenvalidator.ScopeMatchMode;
import org.eclipse.ecsp.tokenvalidator.config.TokenValidatorProperties.CacheProperties;
import org.eclipse.ecsp.tokenvalidator.config.TokenValidatorProperties.MetricsProperties;
import org.eclipse.ecsp.tokenvalidator.config.TokenValidatorProperties.RetryProperties;
import org.eclipse.ecsp.tokenvalidator.config.TokenValidatorProperties.ScopeProperties;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.eclipse.ecsp.tokenvalidator.config.TokenValidatorPropertyNames.PROPERTY_PREFIX;

/**
 * Configuration properties for the token validator library.
 *
 * <p>Binds the full configuration tree from {@code application.yml} or
 * {@code application.properties}. All properties have defaults; only {@code sources}
 * is required (at least one issuer source must be defined).
 *
 * @author Abhishek Kumar
 */
@ConfigurationProperties(prefix = PROPERTY_PREFIX)
public class TokenValidatorProperties {

    /** Creates a new {@code TokenValidatorProperties} instance with default values. */
    public TokenValidatorProperties() {
        // No initialization logic needed; constructor is required to create the configuration instance.
    }

    private List<PublicKeySource> keySources = new ArrayList<>();
    private List<String> whitelistedAlgorithms = List.of("RS256", "ES256");
    private Duration clockSkew = Duration.ZERO;
    private boolean failOnStartupError = true;
    private CacheProperties cache = new CacheProperties();
    private MetricsProperties metrics = new MetricsProperties();
    private RetryProperties jwksRetry = new RetryProperties();
    private ScopeProperties scope = new ScopeProperties();


    /**
     * Returns the list of configured public key sources.
     *
     * @return list of public key sources
     */
    public List<PublicKeySource> getKeySources() {
        return keySources;
    }

    /**
     * Sets the list of configured public key sources.
     *
     * @param keySources list of public key sources
     */
    public void setKeySources(List<PublicKeySource> keySources) {
        this.keySources = keySources;
    }

    /**
     * Returns the whitelisted JWT algorithm names.
     *
     * @return list of allowed algorithm names
     */
    public List<String> getWhitelistedAlgorithms() {
        return whitelistedAlgorithms;
    }

    /**
     * Sets the whitelisted JWT algorithm names.
     *
     * @param whitelistedAlgorithms list of allowed algorithm names
     */
    public void setWhitelistedAlgorithms(List<String> whitelistedAlgorithms) {
        this.whitelistedAlgorithms = whitelistedAlgorithms;
    }

    /**
     * Returns the clock skew tolerance for exp/nbf validation.
     *
     * @return the clock skew duration
     */
    public Duration getClockSkew() {
        return clockSkew;
    }

    /** Maximum permitted clock-skew tolerance (60 seconds). */
    public static final Duration MAX_CLOCK_SKEW = Duration.ofSeconds(60);

    /**
     * Sets the clock skew tolerance for exp/nbf validation.
     *
     * <p>The maximum allowed value is 60 seconds. Providing a larger value is rejected with an
     * {@link IllegalArgumentException}. {@code null} is treated as {@link Duration#ZERO}.
     *
     * @param clockSkew the clock skew duration
     * @throws IllegalArgumentException if the duration is negative or exceeds 60 seconds
     */
    public void setClockSkew(Duration clockSkew) {
        if (clockSkew == null) {
            this.clockSkew = Duration.ZERO;
            return;
        }
        if (clockSkew.isNegative()) {
            throw new IllegalArgumentException("clockSkew must not be negative");
        }
        if (clockSkew.compareTo(MAX_CLOCK_SKEW) > 0) {
            throw new IllegalArgumentException(
                "clockSkew exceeds the maximum allowed value of 60 seconds");
        }
        this.clockSkew = clockSkew;
    }

    /**
     * Returns whether to fail fast on startup key load errors.
     *
     * @return true to fail on startup error, false to continue with empty cache
     */
    public boolean isFailOnStartupError() {
        return failOnStartupError;
    }

    /**
     * Sets whether to fail fast on startup key load errors.
     *
     * @param failOnStartupError true to fail on startup error
     */
    public void setFailOnStartupError(boolean failOnStartupError) {
        this.failOnStartupError = failOnStartupError;
    }

    /**
     * Returns the cache configuration.
     *
     * @return the cache properties
     */
    public CacheProperties getCache() {
        return cache;
    }

    /**
     * Sets the cache configuration.
     *
     * @param cache the cache properties
     */
    public void setCache(CacheProperties cache) {
        this.cache = cache;
    }

    /**
     * Returns the metrics configuration.
     *
     * @return the metrics properties
     */
    public MetricsProperties getMetrics() {
        return metrics;
    }

    /**
     * Sets the metrics configuration.
     *
     * @param metrics the metrics properties
     */
    public void setMetrics(MetricsProperties metrics) {
        this.metrics = metrics;
    }

    /**
     * Returns the JWKS retry strategy configuration.
     *
     * @return the retry properties
     */
    public RetryProperties getJwksRetry() {
        return jwksRetry;
    }

    /**
     * Sets the JWKS retry strategy configuration.
     *
     * @param jwksRetry the retry properties
     */
    public void setJwksRetry(RetryProperties jwksRetry) {
        this.jwksRetry = jwksRetry;
    }

    /**
     * Returns the scope validation configuration.
     *
     * @return the scope properties
     */
    public ScopeProperties getScope() {
        return scope;
    }

    /**
     * Sets the scope validation configuration.
     *
     * @param scope the scope properties
     */
    public void setScope(ScopeProperties scope) {
        this.scope = scope;
    }

    /**
     * Nested scope validation configuration properties.
     *
     * <p>{@code prefixes} — set of scope prefixes to filter by; only token scopes whose
     * name begins with one of these prefixes are considered, and the prefix is stripped
     * before matching. Pass an empty set (default) to accept all scopes without filtering.
     *
     * <p>{@code matchMode} — {@link ScopeMatchMode#ALL} (default) requires every required
     * scope to be present; {@link ScopeMatchMode#ANY} requires at least one match.
     */
    public static class ScopeProperties {

        /** Creates a new {@code ScopeProperties} instance with default values. */
        public ScopeProperties() {
            // No initialization logic needed; constructor is required to create the configuration instance.
        }

        private Set<String> prefixes = new HashSet<>();
        private ScopeMatchMode matchMode = ScopeMatchMode.ALL;

        /**
         * Returns the set of scope prefixes used to filter token scopes.
         *
         * @return the scope prefixes
         */
        public Set<String> getPrefixes() {
            return prefixes;
        }

        /**
         * Sets the set of scope prefixes used to filter token scopes.
         *
         * @param prefixes the scope prefixes
         */
        public void setPrefixes(Set<String> prefixes) {
            this.prefixes = prefixes;
        }

        /**
         * Returns the scope match mode.
         *
         * @return {@link ScopeMatchMode#ALL} or {@link ScopeMatchMode#ANY}
         */
        public ScopeMatchMode getMatchMode() {
            return matchMode;
        }

        /**
         * Sets the scope match mode.
         *
         * @param matchMode {@link ScopeMatchMode#ALL} or {@link ScopeMatchMode#ANY}
         */
        public void setMatchMode(ScopeMatchMode matchMode) {
            this.matchMode = matchMode;
        }
    }

    /**
     * Nested cache configuration properties.
     */
    public static class CacheProperties {

        /** Creates a new {@code CacheProperties} instance with default values. */
        public CacheProperties() {
            // No initialization logic needed; constructor is required to create the configuration instance.
        }

        private int maxSize = 1000;

        /**
         * Returns the maximum cache size.
         *
         * @return the maximum number of entries in the key cache
         */
        public int getMaxSize() {
            return maxSize;
        }

        /**
         * Sets the maximum cache size.
         *
         * @param maxSize the maximum number of entries in the key cache
         */
        public void setMaxSize(int maxSize) {
            this.maxSize = maxSize;
        }
    }

    /**
     * Nested metrics configuration properties.
     */
    public static class MetricsProperties {

        /** Creates a new {@code MetricsProperties} instance with default values. */
        public MetricsProperties() {
            // No initialization logic needed; constructor is required to create the configuration instance.
        }

        private boolean enabled = true;
        private String prefix = PROPERTY_PREFIX;
        private Map<String, String> names = new HashMap<>();
        private List<String> disabledMetrics = new ArrayList<>();

        /**
         * Returns whether metrics are globally enabled.
         *
         * @return true if metrics are enabled
         */
        public boolean isEnabled() {
            return enabled;
        }

        /**
         * Sets whether metrics are globally enabled.
         *
         * @param enabled true to enable metrics
         */
        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        /**
         * Returns the metric prefix.
         *
         * @return the metric prefix string
         */
        public String getPrefix() {
            return prefix;
        }

        /**
         * Sets the metric prefix.
         *
         * @param prefix the metric prefix string
         */
        public void setPrefix(String prefix) {
            this.prefix = prefix;
        }

        /**
         * Returns the per-metric name overrides.
         *
         * @return map of logical key to custom metric name
         */
        public Map<String, String> getNames() {
            return names;
        }

        /**
         * Sets the per-metric name overrides.
         *
         * @param names map of logical key to custom metric name
         */
        public void setNames(Map<String, String> names) {
            this.names = names;
        }

        /**
         * Returns the list of disabled metric logical keys.
         *
         * @return list of disabled metric keys
         */
        public List<String> getDisabledMetrics() {
            return disabledMetrics;
        }

        /**
         * Sets the list of disabled metric logical keys.
         *
         * @param disabledMetrics list of disabled metric keys
         */
        public void setDisabledMetrics(List<String> disabledMetrics) {
            this.disabledMetrics = disabledMetrics;
        }
    }

    /**
     * Nested JWKS retry strategy configuration properties.
     */
    public static class RetryProperties {

        /** Creates a new {@code RetryProperties} instance with default values. */
        public RetryProperties() {
            // No initialization logic needed; constructor is required to create the configuration instance.
        }

        private Duration initialDelay = Duration.ofSeconds(1);
        private int maxAttempts = 3;

        /**
         * Returns the initial delay before the first retry attempt.
         *
         * @return the initial delay duration
         */
        public Duration getInitialDelay() {
            return initialDelay;
        }

        /**
         * Sets the initial delay before the first retry attempt.
         *
         * @param initialDelay the initial delay duration
         */
        public void setInitialDelay(Duration initialDelay) {
            this.initialDelay = initialDelay;
        }

        /**
         * Returns the maximum number of retry attempts (including the first attempt).
         *
         * @return the maximum number of attempts
         */
        public int getMaxAttempts() {
            return maxAttempts;
        }

        /**
         * Sets the maximum number of retry attempts (including the first attempt).
         *
         * @param maxAttempts the maximum number of attempts
         */
        public void setMaxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
        }
    }
}
