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

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.concurrent.TimeUnit;
import java.util.function.IntSupplier;

/**
 * Micrometer-backed implementation of {@link ValidationMetricsRecorder}.
 *
 * <p>Records the seven metrics defined in the design: validations counter,
 * validation duration timer, signature failures counter, cache hits/misses
 * counters, JWKS fetch duration timer, and cache size gauge.
 *
 * <p>This class references {@code io.micrometer.core.instrument} types directly.
 * It must only be instantiated when Micrometer is present on the classpath
 * (enforced by {@code @ConditionalOnClass} in the auto-configuration).
 *
 * @author Abhishek Kumar
 */
public final class MicrometerValidationMetricsRecorder implements ValidationMetricsRecorder {

    private static final String TAG_RESULT = "result";
    private static final String TAG_ISSUER = "issuer";
    private static final String UNKNOWN_ISSUER = "unknown";

    private final MeterRegistry registry;
    private final TokenValidatorMetricsConfig config;

    /**
     * Constructs a MicrometerValidationMetricsRecorder with the given registry and config.
     *
     * @param registry the Micrometer MeterRegistry to record metrics into
     * @param config   the metrics configuration for name overrides and enable/disable settings
     */
    public MicrometerValidationMetricsRecorder(MeterRegistry registry,
                                               TokenValidatorMetricsConfig config) {
        this.registry = registry;
        this.config = config;
    }

    /**
     * Records a token validation attempt counter and timing.
     *
     * @param issuer        the token issuer tag value
     * @param success       whether the validation succeeded
     * @param durationNanos elapsed validation time in nanoseconds
     */
    @Override
    public void recordValidation(String issuer, boolean success, long durationNanos) {
        if (!config.isEnabled()) {
            return;
        }
        String result = success ? "success" : "failure";
        String safeIssuer = issuer != null ? issuer : UNKNOWN_ISSUER;
        if (!config.isDisabled(TokenValidatorMetricsConfig.KEY_VALIDATIONS)) {
            Counter.builder(config.getMetricName(TokenValidatorMetricsConfig.KEY_VALIDATIONS))
                .tag(TAG_RESULT, result)
                .tag(TAG_ISSUER, safeIssuer)
                .register(registry)
                .increment();
        }
        if (!config.isDisabled(TokenValidatorMetricsConfig.KEY_VALIDATION_DURATION)) {
            Timer.builder(config.getMetricName(TokenValidatorMetricsConfig.KEY_VALIDATION_DURATION))
                .tag(TAG_RESULT, result)
                .register(registry)
                .record(durationNanos, TimeUnit.NANOSECONDS);
        }
    }

    /**
     * Records a signature verification failure.
     *
     * @param issuer the token issuer tag value
     */
    @Override
    public void recordSignatureFailure(String issuer) {
        if (!config.isEnabled()
            || config.isDisabled(TokenValidatorMetricsConfig.KEY_SIGNATURE_FAILURES)) {
            return;
        }
        String safeIssuer = issuer != null ? issuer : UNKNOWN_ISSUER;
        Counter.builder(config.getMetricName(TokenValidatorMetricsConfig.KEY_SIGNATURE_FAILURES))
            .tag(TAG_ISSUER, safeIssuer)
            .register(registry)
            .increment();
    }

    /**
     * Records a public-key cache hit.
     *
     * @param issuer the token issuer tag value
     */
    @Override
    public void recordCacheHit(String issuer) {
        if (!config.isEnabled()
            || config.isDisabled(TokenValidatorMetricsConfig.KEY_CACHE_HITS)) {
            return;
        }
        String safeIssuer = issuer != null ? issuer : UNKNOWN_ISSUER;
        Counter.builder(config.getMetricName(TokenValidatorMetricsConfig.KEY_CACHE_HITS))
            .tag(TAG_ISSUER, safeIssuer)
            .register(registry)
            .increment();
    }

    /**
     * Records a public-key cache miss.
     *
     * @param issuer the token issuer tag value
     */
    @Override
    public void recordCacheMiss(String issuer) {
        if (!config.isEnabled()
            || config.isDisabled(TokenValidatorMetricsConfig.KEY_CACHE_MISSES)) {
            return;
        }
        String safeIssuer = issuer != null ? issuer : UNKNOWN_ISSUER;
        Counter.builder(config.getMetricName(TokenValidatorMetricsConfig.KEY_CACHE_MISSES))
            .tag(TAG_ISSUER, safeIssuer)
            .register(registry)
            .increment();
    }

    /**
     * Records a JWKS endpoint fetch duration and outcome.
     *
     * @param issuer        the token issuer tag value
     * @param success       whether the fetch succeeded
     * @param durationNanos elapsed fetch time in nanoseconds
     */
    @Override
    public void recordJwksFetch(String issuer, boolean success, long durationNanos) {
        if (!config.isEnabled()
            || config.isDisabled(TokenValidatorMetricsConfig.KEY_JWKS_FETCH_DURATION)) {
            return;
        }
        String safeIssuer = issuer != null ? issuer : UNKNOWN_ISSUER;
        Timer.builder(config.getMetricName(TokenValidatorMetricsConfig.KEY_JWKS_FETCH_DURATION))
            .tag(TAG_ISSUER, safeIssuer)
            .tag(TAG_RESULT, success ? "success" : "failure")
            .register(registry)
            .record(durationNanos, TimeUnit.NANOSECONDS);
    }

    /**
     * Registers a Gauge for the public-key cache size.
     *
     * @param sizeSupplier supplier returning the current cache entry count
     */
    @Override
    public void bindCacheSizeGauge(IntSupplier sizeSupplier) {
        if (!config.isEnabled()
            || config.isDisabled(TokenValidatorMetricsConfig.KEY_CACHE_SIZE)) {
            return;
        }
        Gauge.builder(config.getMetricName(TokenValidatorMetricsConfig.KEY_CACHE_SIZE),
                sizeSupplier, IntSupplier::getAsInt)
            .strongReference(true)
            .register(registry);
    }
}
