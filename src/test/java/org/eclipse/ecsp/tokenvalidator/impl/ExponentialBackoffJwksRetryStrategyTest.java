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

import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.util.Optional;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link ExponentialBackoffJwksRetryStrategy}.
 *
 * @author Abhishek Kumar
 */
class ExponentialBackoffJwksRetryStrategyTest {

    private static final long BASE_DELAY_MS = 10L;
    private static final long LONG_DELAY_MS = 100L;
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final int ATTEMPT_TWO = 2;
    private static final int ATTEMPT_THREE = 3;

    @Test
    void firstAttemptShouldRetry() {
        ExponentialBackoffJwksRetryStrategy strategy =
            new ExponentialBackoffJwksRetryStrategy(Duration.ofMillis(BASE_DELAY_MS), MAX_RETRY_ATTEMPTS);
        Optional<Duration> delay = strategy.decideRetry(1, new RuntimeException("error"));
        assertTrue(delay.isPresent());
    }

    @Test
    void secondAttemptDoubleDelay() {
        ExponentialBackoffJwksRetryStrategy strategy =
            new ExponentialBackoffJwksRetryStrategy(Duration.ofMillis(LONG_DELAY_MS), MAX_RETRY_ATTEMPTS);
        Optional<Duration> delay1 = strategy.decideRetry(1, new RuntimeException("err"));
        Optional<Duration> delay2 = strategy.decideRetry(ATTEMPT_TWO, new RuntimeException("err"));
        assertTrue(delay1.isPresent());
        assertTrue(delay2.isPresent());
        assertTrue(delay2.get().compareTo(delay1.get()) >= 0);
    }

    @Test
    void maxAttemptsReturnsEmpty() {
        ExponentialBackoffJwksRetryStrategy strategy =
            new ExponentialBackoffJwksRetryStrategy(Duration.ofMillis(BASE_DELAY_MS), MAX_RETRY_ATTEMPTS);
        Optional<Duration> delay = strategy.decideRetry(ATTEMPT_THREE, new RuntimeException("error"));
        assertFalse(delay.isPresent());
    }

    @Test
    void defaultConstructorMaxThreeAttempts() {
        ExponentialBackoffJwksRetryStrategy strategy = new ExponentialBackoffJwksRetryStrategy();
        assertTrue(strategy.decideRetry(1, new RuntimeException("e")).isPresent());
        assertTrue(strategy.decideRetry(ATTEMPT_TWO, new RuntimeException("e")).isPresent());
        assertFalse(strategy.decideRetry(ATTEMPT_THREE, new RuntimeException("e")).isPresent());
    }
}
