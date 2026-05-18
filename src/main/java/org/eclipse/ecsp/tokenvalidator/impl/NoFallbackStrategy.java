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

import org.eclipse.ecsp.tokenvalidator.FallbackKeyStrategy;
import org.eclipse.ecsp.tokenvalidator.PublicKeyCache;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import java.util.Optional;

/**
 * A fallback key strategy that always returns empty, causing validation to fail fast.
 *
 * <p>Appropriate for environments where every token carries a {@code kid} matching a
 * key pre-loaded at startup. Using this strategy means that if no key is found in
 * cache, validation immediately fails with {@code KeyNotFoundException}.
 *
 * @author Abhishek Kumar
 */
public class NoFallbackStrategy implements FallbackKeyStrategy {

    /**
     * Constructs a new NoFallbackStrategy.
     */
    public NoFallbackStrategy() {
        // No-args constructor for bean registration in the Spring application context
    }

    /**
     * Always returns empty, causing key lookup to fail fast.
     *
     * @param issuer the token issuer
     * @param kid    the key ID that was not found
     * @param cache  the public key cache (not consulted)
     * @return always {@link Optional#empty()}
     */
    @Override
    public Optional<PublicKeyInfo> findFallback(String issuer, String kid, PublicKeyCache cache) {
        return Optional.empty();
    }
}
