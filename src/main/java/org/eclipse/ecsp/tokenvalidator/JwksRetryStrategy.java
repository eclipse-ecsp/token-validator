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

package org.eclipse.ecsp.tokenvalidator;

import java.time.Duration;
import java.util.Optional;

/**
 * Controls retry timing and limits for JWKS endpoint fetch attempts.
 *
 * <p>Injected into {@code JwksPublicKeyLoader}; replaces the internal
 * {@code ExponentialBackoffRetryPolicy}.
 *
 * @author Abhishek Kumar
 */
public interface JwksRetryStrategy {

    /**
     * Decides whether and how long to wait before retrying a failed JWKS fetch.
     *
     * @param attempt       the current attempt number (1-based)
     * @param lastException the exception thrown by the previous attempt
     * @return Optional containing the Duration to wait before retry, or empty to stop retrying
     */
    Optional<Duration> decideRetry(int attempt, Exception lastException);
}
