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

import java.util.function.IntSupplier;

/**
 * No-operation implementation of {@link ValidationMetricsRecorder}.
 *
 * <p>Used as the default when Micrometer is not on the classpath or when the
 * caller does not configure a metrics recorder. All methods are empty stubs.
 *
 * @author Abhishek Kumar
 */
public final class NoopValidationMetricsRecorder implements ValidationMetricsRecorder {

    /** Singleton instance — stateless, safe to share. */
    public static final NoopValidationMetricsRecorder INSTANCE = new NoopValidationMetricsRecorder();

    /**
     * Constructs a new NoopValidationMetricsRecorder.
     */
    public NoopValidationMetricsRecorder() {
        // No-args constructor for bean registration in the Spring application context
    }

    @Override
    public void recordValidation(String issuer, boolean success, long durationNanos) {
        // no-op
    }

    @Override
    public void recordSignatureFailure(String issuer) {
        // no-op
    }

    @Override
    public void recordCacheHit(String issuer) {
        // no-op
    }

    @Override
    public void recordCacheMiss(String issuer) {
        // no-op
    }

    @Override
    public void recordJwksFetch(String issuer, boolean success, long durationNanos) {
        // no-op
    }

    @Override
    public void bindCacheSizeGauge(IntSupplier sizeSupplier) {
        // no-op
    }
}
