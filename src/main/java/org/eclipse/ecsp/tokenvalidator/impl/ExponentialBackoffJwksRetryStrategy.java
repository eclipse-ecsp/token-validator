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

import org.eclipse.ecsp.tokenvalidator.JwksRetryStrategy;
import java.time.Duration;
import java.util.Optional;

/**
 * Exponential backoff retry strategy for JWKS endpoint fetch attempts.
 *
 * <p>Waits {@code initialDelay * 2^(attempt-1)} before each retry attempt.
 * Stops retrying after {@code maxAttempts}.
 *
 * @author Abhishek Kumar
 */
public class ExponentialBackoffJwksRetryStrategy implements JwksRetryStrategy {

    /** Default initial delay between retry attempts. */
    public static final Duration DEFAULT_INITIAL_DELAY = Duration.ofSeconds(1);

    /** Default maximum number of retry attempts. */
    public static final int DEFAULT_MAX_ATTEMPTS = 3;

    private final Duration initialDelay;
    private final int maxAttempts;

    /**
     * Constructs an ExponentialBackoffJwksRetryStrategy with default settings.
     */
    public ExponentialBackoffJwksRetryStrategy() {
        this(DEFAULT_INITIAL_DELAY, DEFAULT_MAX_ATTEMPTS);
    }

    /**
     * Constructs an ExponentialBackoffJwksRetryStrategy with custom settings.
     *
     * @param initialDelay the initial delay before the first retry
     * @param maxAttempts  the maximum number of attempts (including the first)
     */
    public ExponentialBackoffJwksRetryStrategy(Duration initialDelay, int maxAttempts) {
        this.initialDelay = initialDelay;
        this.maxAttempts = maxAttempts;
    }

    /**
     * Decides the wait duration before the next retry, or stops retrying.
     *
     * @param attempt       the current attempt number (1-based)
     * @param lastException the exception thrown by the previous attempt
     * @return Optional containing the Duration to wait, or empty to stop retrying
     */
    @Override
    public Optional<Duration> decideRetry(int attempt, Exception lastException) {
        if (attempt >= maxAttempts) {
            return Optional.empty();
        }
        long delayMs = initialDelay.toMillis() * (1L << (attempt - 1));
        return Optional.of(Duration.ofMillis(delayMs));
    }
}
