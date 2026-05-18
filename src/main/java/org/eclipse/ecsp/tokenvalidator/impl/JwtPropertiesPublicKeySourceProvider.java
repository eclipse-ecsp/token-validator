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

import org.eclipse.ecsp.tokenvalidator.PublicKeySourceProvider;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import java.util.List;

/**
 * Wraps {@code TokenValidatorProperties} to provide the list of configured key sources.
 *
 * <p>This is the default {@link PublicKeySourceProvider} used by auto-configuration.
 * It resolves key sources once from the bound properties and returns them.
 *
 * @author Abhishek Kumar
 */
public class JwtPropertiesPublicKeySourceProvider implements PublicKeySourceProvider {

    private final List<PublicKeySource> sources;

    /**
     * Constructs a JwtPropertiesPublicKeySourceProvider with the given key sources.
     *
     * @param sources the list of configured public key sources
     */
    public JwtPropertiesPublicKeySourceProvider(List<PublicKeySource> sources) {
        this.sources = sources != null ? List.copyOf(sources) : List.of();
    }

    /**
     * Returns the list of configured public key sources.
     *
     * @return list of PublicKeySource configurations
     */
    @Override
    public List<PublicKeySource> keySources() {
        return sources;
    }
}
