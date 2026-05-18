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

import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyType;
import java.io.Closeable;
import java.security.PublicKey;
import java.util.Map;

/**
 * Loads a public key from a given source configuration.
 *
 * <p>Implementations handle loading from different source types (PEM files, JWKS URLs).
 * Implements {@link Closeable} to allow resource cleanup.
 *
 * @author Abhishek Kumar
 */
public interface PublicKeyLoader extends Closeable {

    /**
     * Loads public keys from the provided configuration.
     *
     * @param config the public key source configuration
     * @return map of key ID to public key
     */
    Map<String, PublicKey> loadKeys(PublicKeySource config);

    /**
     * Returns the type of public key source this loader supports.
     *
     * @return the PublicKeyType this loader handles
     */
    PublicKeyType getType();
}
