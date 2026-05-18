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

import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link JwtPropertiesPublicKeySourceProvider}.
 *
 * @author Abhishek Kumar
 */
class JwtPropertiesPublicKeySourceProviderTest {

    @Test
    void returnsConfiguredSources() {
        PublicKeySource source = new PublicKeySource();
        source.setId("k1");
        source.setIssuer("iss1");
        JwtPropertiesPublicKeySourceProvider provider =
            new JwtPropertiesPublicKeySourceProvider(List.of(source));
        assertEquals(1, provider.keySources().size());
        assertEquals("k1", provider.keySources().get(0).getId());
    }

    @Test
    void nullSourcesReturnsEmpty() {
        JwtPropertiesPublicKeySourceProvider provider =
            new JwtPropertiesPublicKeySourceProvider(null);
        assertTrue(provider.keySources().isEmpty());
    }

    @Test
    void emptySourcesReturnsEmpty() {
        JwtPropertiesPublicKeySourceProvider provider =
            new JwtPropertiesPublicKeySourceProvider(List.of());
        assertTrue(provider.keySources().isEmpty());
    }
}
