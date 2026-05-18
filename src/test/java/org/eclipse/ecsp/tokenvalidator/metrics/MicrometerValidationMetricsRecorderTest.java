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
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for {@link MicrometerValidationMetricsRecorder}.
 *
 * @author Abhishek Kumar
 */
class MicrometerValidationMetricsRecorderTest {

    private static final double DELTA = 0.001;
    private static final long DURATION_NANOS = TimeUnit.MILLISECONDS.toNanos(50);
    private static final int CACHE_SIZE_VALUE = 42;
    private static final int CACHE_SIZE_GLOBAL_DISABLED = 5;
    private static final int CACHE_SIZE_GAUGE_DISABLED = 10;

    private SimpleMeterRegistry registry;
    private TokenValidatorMetricsConfig config;
    private MicrometerValidationMetricsRecorder recorder;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        config = TokenValidatorMetricsConfig.builder().build();
        recorder = new MicrometerValidationMetricsRecorder(registry, config);
    }

    @Test
    void recordValidationSuccessIncreasesCounter() {
        recorder.recordValidation("https://issuer.example.com", true, DURATION_NANOS);

        Counter counter = registry.find("token.validator.validations")
            .tag("result", "success")
            .tag("issuer", "https://issuer.example.com")
            .counter();
        assertNotNull(counter);
        assertEquals(1.0, counter.count(), DELTA);
    }

    @Test
    void recordValidationFailureIncreasesCounter() {
        recorder.recordValidation("issuer1", false, DURATION_NANOS);

        Counter counter = registry.find("token.validator.validations")
            .tag("result", "failure")
            .tag("issuer", "issuer1")
            .counter();
        assertNotNull(counter);
        assertEquals(1.0, counter.count(), DELTA);
    }

    @Test
    void recordValidationRecordsDuration() {
        recorder.recordValidation("issuer1", true, DURATION_NANOS);

        Timer timer = registry.find("token.validator.validation.duration")
            .tag("result", "success")
            .timer();
        assertNotNull(timer);
        assertEquals(1, timer.count());
    }

    @Test
    void recordValidationNullIssuerUsesUnknown() {
        recorder.recordValidation(null, true, DURATION_NANOS);

        Counter counter = registry.find("token.validator.validations")
            .tag("issuer", "unknown")
            .counter();
        assertNotNull(counter);
    }

    @Test
    void recordSignatureFailureIncreasesCounter() {
        recorder.recordSignatureFailure("issuer1");

        Counter counter = registry.find("token.validator.signature.failures")
            .tag("issuer", "issuer1")
            .counter();
        assertNotNull(counter);
        assertEquals(1.0, counter.count(), DELTA);
    }

    @Test
    void recordSignatureFailureNullIssuerUsesUnknown() {
        recorder.recordSignatureFailure(null);

        Counter counter = registry.find("token.validator.signature.failures")
            .tag("issuer", "unknown")
            .counter();
        assertNotNull(counter);
    }

    @Test
    void recordCacheHitIncreasesCounter() {
        recorder.recordCacheHit("issuer1");

        Counter counter = registry.find("token.validator.key.cache.hits")
            .tag("issuer", "issuer1")
            .counter();
        assertNotNull(counter);
        assertEquals(1.0, counter.count(), DELTA);
    }

    @Test
    void recordCacheMissIncreasesCounter() {
        recorder.recordCacheMiss("issuer1");

        Counter counter = registry.find("token.validator.key.cache.misses")
            .tag("issuer", "issuer1")
            .counter();
        assertNotNull(counter);
        assertEquals(1.0, counter.count(), DELTA);
    }

    @Test
    void recordJwksFetchSuccessRecordsTimer() {
        recorder.recordJwksFetch("issuer1", true, DURATION_NANOS);

        Timer timer = registry.find("token.validator.jwks.fetch.duration")
            .tag("issuer", "issuer1")
            .tag("result", "success")
            .timer();
        assertNotNull(timer);
        assertEquals(1, timer.count());
    }

    @Test
    void recordJwksFetchFailureRecordsTimer() {
        recorder.recordJwksFetch("issuer1", false, DURATION_NANOS);

        Timer timer = registry.find("token.validator.jwks.fetch.duration")
            .tag("result", "failure")
            .timer();
        assertNotNull(timer);
    }

    @Test
    void bindCacheSizeGaugeRegistersGauge() {
        final int[] sizeHolder = {CACHE_SIZE_VALUE};
        recorder.bindCacheSizeGauge(() -> sizeHolder[0]);

        Gauge gauge = registry.find("token.validator.key.cache.size").gauge();
        assertNotNull(gauge);
        assertEquals(CACHE_SIZE_VALUE, gauge.value(), DELTA);
    }

    @Test
    void disabledConfigSkipsValidationCounter() {
        TokenValidatorMetricsConfig disabledConfig = TokenValidatorMetricsConfig.builder()
            .disableMetric(TokenValidatorMetricsConfig.KEY_VALIDATIONS)
            .build();
        MicrometerValidationMetricsRecorder rec =
            new MicrometerValidationMetricsRecorder(registry, disabledConfig);

        rec.recordValidation("issuer1", true, DURATION_NANOS);

        Counter counter = registry.find("token.validator.validations").counter();
        assertEquals(null, counter);
    }

    @Test
    void globallyDisabledConfigSkipsAllMetrics() {
        TokenValidatorMetricsConfig disabledAll = TokenValidatorMetricsConfig.builder()
            .enabled(false)
            .build();
        MicrometerValidationMetricsRecorder rec =
            new MicrometerValidationMetricsRecorder(registry, disabledAll);

        rec.recordValidation("issuer1", true, DURATION_NANOS);
        rec.recordSignatureFailure("issuer1");
        rec.recordCacheHit("issuer1");
        rec.recordCacheMiss("issuer1");
        rec.recordJwksFetch("issuer1", true, DURATION_NANOS);
        rec.bindCacheSizeGauge(() -> CACHE_SIZE_GLOBAL_DISABLED);

        assertEquals(0, registry.getMeters().size());
    }

    @Test
    void customPrefixIsApplied() {
        TokenValidatorMetricsConfig customConfig = TokenValidatorMetricsConfig.builder()
            .prefix("my.service")
            .build();
        MicrometerValidationMetricsRecorder rec =
            new MicrometerValidationMetricsRecorder(registry, customConfig);

        rec.recordValidation("issuer1", true, DURATION_NANOS);

        Counter counter = registry.find("my.service.validations").counter();
        assertNotNull(counter);
    }

    @Test
    void disabledCacheSizeGaugeSkipsRegistration() {
        TokenValidatorMetricsConfig noGaugeConfig = TokenValidatorMetricsConfig.builder()
            .disableMetric(TokenValidatorMetricsConfig.KEY_CACHE_SIZE)
            .build();
        MicrometerValidationMetricsRecorder rec =
            new MicrometerValidationMetricsRecorder(registry, noGaugeConfig);

        rec.bindCacheSizeGauge(() -> CACHE_SIZE_GAUGE_DISABLED);

        Gauge gauge = registry.find("token.validator.key.cache.size").gauge();
        assertEquals(null, gauge);
    }

    @Test
    void disabledValidationDurationSkipsTimer() {
        TokenValidatorMetricsConfig noTimerConfig = TokenValidatorMetricsConfig.builder()
            .disableMetric(TokenValidatorMetricsConfig.KEY_VALIDATION_DURATION)
            .build();
        MicrometerValidationMetricsRecorder rec =
            new MicrometerValidationMetricsRecorder(registry, noTimerConfig);

        rec.recordValidation("issuer1", true, DURATION_NANOS);

        Timer timer = registry.find("token.validator.validation.duration").timer();
        assertEquals(null, timer);
    }

    @Test
    void disabledSignatureFailuresSkipsCounter() {
        TokenValidatorMetricsConfig cfg = TokenValidatorMetricsConfig.builder()
            .disableMetric(TokenValidatorMetricsConfig.KEY_SIGNATURE_FAILURES)
            .build();
        MicrometerValidationMetricsRecorder rec =
            new MicrometerValidationMetricsRecorder(registry, cfg);

        rec.recordSignatureFailure("issuer1");

        Counter counter = registry.find("token.validator.signature.failures").counter();
        assertEquals(null, counter);
    }

    @Test
    void disabledCacheHitsSkipsCounter() {
        TokenValidatorMetricsConfig cfg = TokenValidatorMetricsConfig.builder()
            .disableMetric(TokenValidatorMetricsConfig.KEY_CACHE_HITS)
            .build();
        MicrometerValidationMetricsRecorder rec =
            new MicrometerValidationMetricsRecorder(registry, cfg);

        rec.recordCacheHit("issuer1");

        Counter counter = registry.find("token.validator.key.cache.hits").counter();
        assertEquals(null, counter);
    }

    @Test
    void disabledCacheMissesSkipsCounter() {
        TokenValidatorMetricsConfig cfg = TokenValidatorMetricsConfig.builder()
            .disableMetric(TokenValidatorMetricsConfig.KEY_CACHE_MISSES)
            .build();
        MicrometerValidationMetricsRecorder rec =
            new MicrometerValidationMetricsRecorder(registry, cfg);

        rec.recordCacheMiss("issuer1");

        Counter counter = registry.find("token.validator.key.cache.misses").counter();
        assertEquals(null, counter);
    }

    @Test
    void disabledJwksFetchSkipsTimer() {
        TokenValidatorMetricsConfig cfg = TokenValidatorMetricsConfig.builder()
            .disableMetric(TokenValidatorMetricsConfig.KEY_JWKS_FETCH_DURATION)
            .build();
        MicrometerValidationMetricsRecorder rec =
            new MicrometerValidationMetricsRecorder(registry, cfg);

        rec.recordJwksFetch("issuer1", true, DURATION_NANOS);

        Timer timer = registry.find("token.validator.jwks.fetch.duration").timer();
        assertEquals(null, timer);
    }

    @Test
    void nullIssuerForJwksFetchUsesUnknown() {
        recorder.recordJwksFetch(null, true, DURATION_NANOS);

        Timer timer = registry.find("token.validator.jwks.fetch.duration")
            .tag("issuer", "unknown")
            .timer();
        assertNotNull(timer);
    }

    @Test
    void nullIssuerForCacheHitUsesUnknown() {
        recorder.recordCacheHit(null);

        Counter counter = registry.find("token.validator.key.cache.hits")
            .tag("issuer", "unknown")
            .counter();
        assertNotNull(counter);
    }

    @Test
    void nullIssuerForCacheMissUsesUnknown() {
        recorder.recordCacheMiss(null);

        Counter counter = registry.find("token.validator.key.cache.misses")
            .tag("issuer", "unknown")
            .counter();
        assertNotNull(counter);
    }
}
