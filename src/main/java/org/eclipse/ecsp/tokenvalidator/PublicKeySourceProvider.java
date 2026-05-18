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
import java.util.List;

/**
 * Provides sources for public keys used in JWT validation.
 *
 * <p>Implementations load public key source configuration from various sources
 * (e.g. application properties, external configuration).
 *
 * @author Abhishek Kumar
 */
public interface PublicKeySourceProvider {

    /**
     * Returns a list of public key sources.
     *
     * <p>This method is used to retrieve the configurations for public key sources
     * that can be used by the {@link PublicKeyLoader} to load public keys.
     *
     * @return list of PublicKeySource configurations
     */
    List<PublicKeySource> keySources();
}
