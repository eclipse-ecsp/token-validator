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

import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import java.util.Optional;

/**
 * Determines how to resolve a public key when the primary kid-based lookup yields no result.
 *
 * <p>Implementations may inspect the cache for a default-key entry, use an injected
 * {@code PublicKeyLoader} to load a key from the file system or another configured source,
 * or fail fast.
 *
 * <p>{@code DefaultFallbackKeyStrategy} accepts an optional {@code PemPublicKeyLoader};
 * when present it attempts a file-system load before returning {@code Optional.empty()}.
 *
 * @author Abhishek Kumar
 */
public interface FallbackKeyStrategy {

    /**
     * Attempts to find a fallback key when the primary lookup fails.
     *
     * @param issuer the token issuer
     * @param kid    the key ID that was not found (may be null)
     * @param cache  the public key cache to query for fallback candidates
     * @return Optional containing a fallback key, or empty if no fallback is available
     */
    Optional<PublicKeyInfo> findFallback(String issuer, String kid, PublicKeyCache cache);
}
