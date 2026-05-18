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

import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
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

    private List<PublicKeySource> sources = new ArrayList<>();
    private List<String> whitelistedAlgorithms = List.of("RS256", "ES256");
    private Duration clockSkew = Duration.ZERO;
    private boolean failOnStartupError = true;
    private CacheProperties cache = new CacheProperties();
    private MetricsProperties metrics = new MetricsProperties();

    /**
     * Returns the list of configured public key sources.
     *
     * @return list of public key sources
     */
    public List<PublicKeySource> getSources() {
        return sources;
    }

    /**
     * Sets the list of configured public key sources.
     *
     * @param sources list of public key sources
     */
    public void setSources(List<PublicKeySource> sources) {
        this.sources = sources;
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

    /**
     * Sets the clock skew tolerance for exp/nbf validation.
     *
     * @param clockSkew the clock skew duration
     */
    public void setClockSkew(Duration clockSkew) {
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
     * Nested cache configuration properties.
     */
    public static class CacheProperties {

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
}
