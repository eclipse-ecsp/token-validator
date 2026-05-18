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

package org.eclipse.ecsp.tokenvalidator.metrics;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import static org.eclipse.ecsp.tokenvalidator.config.TokenValidatorPropertyNames.PROPERTY_PREFIX;

/**
 * Optional value object that customises Micrometer metric recording for the token validator.
 *
 * <p>Supports global enable/disable, prefix override, per-metric name override,
 * and per-metric suppression. When absent from the builder, all metrics are enabled
 * with default names. When Micrometer is not on the classpath, metric recording is silently
 * skipped regardless of configuration.
 *
 * @author Abhishek Kumar
 */
public final class TokenValidatorMetricsConfig {

    /** Logical key: total token validation attempts. */
    public static final String KEY_VALIDATIONS = "validations";

    /** Logical key: end-to-end validation latency. */
    public static final String KEY_VALIDATION_DURATION = "validation.duration";

    /** Logical key: signature verification failures. */
    public static final String KEY_SIGNATURE_FAILURES = "signature.failures";

    /** Logical key: public key cache hits. */
    public static final String KEY_CACHE_HITS = "key.cache.hits";

    /** Logical key: public key cache misses. */
    public static final String KEY_CACHE_MISSES = "key.cache.misses";

    /** Logical key: JWKS endpoint fetch latency. */
    public static final String KEY_JWKS_FETCH_DURATION = "jwks.fetch.duration";

    /** Logical key: current public key cache size. */
    public static final String KEY_CACHE_SIZE = "key.cache.size";

    private static final String DEFAULT_PREFIX = PROPERTY_PREFIX;

    private static final Map<String, String> DEFAULT_NAMES;

    static {
        Map<String, String> names = new HashMap<>();
        names.put(KEY_VALIDATIONS, KEY_VALIDATIONS);
        names.put(KEY_VALIDATION_DURATION, KEY_VALIDATION_DURATION);
        names.put(KEY_SIGNATURE_FAILURES, KEY_SIGNATURE_FAILURES);
        names.put(KEY_CACHE_HITS, KEY_CACHE_HITS);
        names.put(KEY_CACHE_MISSES, KEY_CACHE_MISSES);
        names.put(KEY_JWKS_FETCH_DURATION, KEY_JWKS_FETCH_DURATION);
        names.put(KEY_CACHE_SIZE, KEY_CACHE_SIZE);
        DEFAULT_NAMES = Collections.unmodifiableMap(names);
    }

    private final boolean enabled;
    private final String prefix;
    private final Map<String, String> metricNames;
    private final Set<String> disabledMetrics;

    private TokenValidatorMetricsConfig(Builder builderInstance) {
        this.enabled = builderInstance.enabled;
        this.prefix = builderInstance.prefix;
        this.metricNames = Collections.unmodifiableMap(new HashMap<>(builderInstance.metricNames));
        this.disabledMetrics = Collections.unmodifiableSet(new HashSet<>(builderInstance.disabledMetrics));
    }

    /**
     * Returns whether metric recording is globally enabled.
     *
     * @return true if enabled, false if all metrics are suppressed
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Returns the metric name prefix (default: {@code "token.validator"}).
     *
     * @return the metric prefix
     */
    public String getPrefix() {
        return prefix;
    }

    /**
     * Returns the fully-qualified metric name for the given logical key.
     *
     * <p>Applies any per-metric name override, then prepends the prefix.
     *
     * @param logicalKey the logical metric key (e.g. {@link #KEY_VALIDATIONS})
     * @return the full metric name
     */
    public String getMetricName(String logicalKey) {
        String suffix = metricNames.getOrDefault(logicalKey,
            DEFAULT_NAMES.getOrDefault(logicalKey, logicalKey));
        return prefix + "." + suffix;
    }

    /**
     * Returns whether the given metric is suppressed.
     *
     * @param logicalKey the logical metric key
     * @return true if this metric should not be recorded
     */
    public boolean isDisabled(String logicalKey) {
        return !enabled || disabledMetrics.contains(logicalKey);
    }

    /**
     * Creates a new builder for {@link TokenValidatorMetricsConfig}.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link TokenValidatorMetricsConfig}.
     */
    public static final class Builder {

        private boolean enabled = true;
        private String prefix = DEFAULT_PREFIX;
        private final Map<String, String> metricNames = new HashMap<>();
        private final Set<String> disabledMetrics = new HashSet<>();

        private Builder() {
        }

        /**
         * Enables or disables all metric recording globally.
         *
         * @param enabledFlag true to enable, false to disable all metrics
         * @return this builder
         */
        public Builder enabled(boolean enabledFlag) {
            this.enabled = enabledFlag;
            return this;
        }

        /**
         * Sets the metric prefix (replaces the default {@code "token.validator"}).
         *
         * @param metricPrefix the new prefix
         * @return this builder
         */
        public Builder prefix(String metricPrefix) {
            this.prefix = metricPrefix != null ? metricPrefix : DEFAULT_PREFIX;
            return this;
        }

        /**
         * Overrides the metric name for a specific logical key.
         *
         * @param logicalKey the logical metric key
         * @param customName the custom metric name suffix
         * @return this builder
         */
        public Builder metricName(String logicalKey, String customName) {
            this.metricNames.put(logicalKey, customName);
            return this;
        }

        /**
         * Suppresses the metric for a specific logical key.
         *
         * @param logicalKey the logical metric key to disable
         * @return this builder
         */
        public Builder disableMetric(String logicalKey) {
            this.disabledMetrics.add(logicalKey);
            return this;
        }

        /**
         * Builds and returns the {@link TokenValidatorMetricsConfig}.
         *
         * @return the configured metrics config
         */
        public TokenValidatorMetricsConfig build() {
            return new TokenValidatorMetricsConfig(this);
        }
    }
}
