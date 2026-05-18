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
 * Service interface for managing public keys used in JWT validation.
 *
 * <p>Provides methods to find and refresh public keys. Coordinates key lookup
 * and refresh across all configured sources.
 *
 * @author Abhishek Kumar
 */
public interface PublicKeyManager {

    /**
     * Finds a public key by its ID and issuer.
     *
     * @param keyId  the identifier of the public key (may be null)
     * @param issuer the issuer of the JWT
     * @return an Optional containing the PublicKeyInfo if found, otherwise empty
     */
    Optional<PublicKeyInfo> findPublicKey(String keyId, String issuer);

    /**
     * Refreshes the public keys from all configured sources.
     *
     * <p>This method should be called to reload keys when they are updated or changed.
     */
    void refreshPublicKeys();

    /**
     * Refreshes the public keys for a specific issuer only.
     *
     * @param issuer the issuer whose keys should be refreshed
     */
    void refreshPublicKeys(String issuer);
}
