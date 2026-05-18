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

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for {@link NoopValidationMetricsRecorder}.
 *
 * @author Abhishek Kumar
 */
class NoopValidationMetricsRecorderTest {

    private static final long DURATION_NANOS = 1000L;
    private static final int CACHE_SIZE = 42;

    private final NoopValidationMetricsRecorder recorder = NoopValidationMetricsRecorder.INSTANCE;

    @Test
    void instanceIsNotNull() {
        assertNotNull(NoopValidationMetricsRecorder.INSTANCE);
    }

    @Test
    void constructorCreatesInstance() {
        assertNotNull(new NoopValidationMetricsRecorder());
    }

    @Test
    void recordValidationDoesNotThrow() {
        assertDoesNotThrow(() -> recorder.recordValidation("issuer", true, DURATION_NANOS));
    }

    @Test
    void recordSignatureFailureDoesNotThrow() {
        assertDoesNotThrow(() -> recorder.recordSignatureFailure("issuer"));
    }

    @Test
    void recordCacheHitDoesNotThrow() {
        assertDoesNotThrow(() -> recorder.recordCacheHit("issuer"));
    }

    @Test
    void recordCacheMissDoesNotThrow() {
        assertDoesNotThrow(() -> recorder.recordCacheMiss("issuer"));
    }

    @Test
    void recordJwksFetchDoesNotThrow() {
        assertDoesNotThrow(() -> recorder.recordJwksFetch("issuer", true, DURATION_NANOS));
    }

    @Test
    void bindCacheSizeGaugeDoesNotThrow() {
        assertDoesNotThrow(() -> recorder.bindCacheSizeGauge(() -> CACHE_SIZE));
    }
}
