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
 * Abstraction for recording token-validator operational metrics.
 *
 * <p>Decouples core validation classes from any specific metrics framework.
 * The default implementation is {@link NoopValidationMetricsRecorder}; when
 * Micrometer is on the classpath the auto-configuration registers
 * {@code MicrometerValidationMetricsRecorder} instead.
 *
 * <p>All duration values are expressed in nanoseconds as returned by
 * {@link System#nanoTime()}.
 *
 * @author Abhishek Kumar
 */
public interface ValidationMetricsRecorder {

    /**
     * Records the outcome and elapsed time for a single token validation attempt.
     *
     * @param issuer        the {@code iss} claim extracted from the token (or {@code "unknown"}
     *                      if parsing failed before the issuer could be read)
     * @param success       {@code true} if the full pipeline completed without exception
     * @param durationNanos elapsed time of the validation call in nanoseconds
     */
    void recordValidation(String issuer, boolean success, long durationNanos);

    /**
     * Records a JWT signature verification failure.
     *
     * @param issuer the issuer whose key was used during the failed verification attempt
     */
    void recordSignatureFailure(String issuer);

    /**
     * Records a public-key cache hit.
     *
     * @param issuer the issuer for which a cached key was found
     */
    void recordCacheHit(String issuer);

    /**
     * Records a public-key cache miss.
     *
     * @param issuer the issuer for which no cached key was found
     */
    void recordCacheMiss(String issuer);

    /**
     * Records the elapsed time and outcome of a JWKS endpoint fetch attempt.
     *
     * @param issuer        the issuer whose JWKS endpoint was contacted
     * @param success       {@code true} if all keys were successfully loaded
     * @param durationNanos elapsed time of the fetch (including retries) in nanoseconds
     */
    void recordJwksFetch(String issuer, boolean success, long durationNanos);

    /**
     * Registers a gauge that reports the current public-key cache size.
     *
     * <p>Called once at startup after the cache has been created. Implementations
     * that do not support gauges may leave this method empty.
     *
     * @param sizeSupplier a supplier that returns the current number of entries in the cache
     */
    void bindCacheSizeGauge(IntSupplier sizeSupplier);
}
