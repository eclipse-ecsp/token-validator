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

package org.eclipse.ecsp.tokenvalidator.model;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link PublicKeySource} getters/setters.
 *
 * @author Abhishek Kumar
 */
class PublicKeySourceTest {

    private static final int REFRESH_INTERVAL_MINUTES = 5;

    @Test
    void defaultValues() {
        PublicKeySource source = new PublicKeySource();
        assertNull(source.getId());
        assertNull(source.getIssuer());
        assertNull(source.getUrl());
        assertNull(source.getLocation());
        assertNull(source.getRefreshInterval());
        assertNull(source.getAudience());
        assertFalse(source.isDefault());
    }

    @Test
    void settersAndGetters() {
        PublicKeySource source = new PublicKeySource();
        source.setId("id1");
        source.setIssuer("iss1");
        source.setUrl("https://example.com/jwks");
        source.setLocation("/path/key.pem");
        source.setRefreshInterval(Duration.ofMinutes(REFRESH_INTERVAL_MINUTES));
        source.setAudience("my-service");
        source.setDefault(true);

        assertEquals("id1", source.getId());
        assertEquals("iss1", source.getIssuer());
        assertEquals("https://example.com/jwks", source.getUrl());
        assertEquals("/path/key.pem", source.getLocation());
        assertEquals(Duration.ofMinutes(REFRESH_INTERVAL_MINUTES), source.getRefreshInterval());
        assertEquals("my-service", source.getAudience());
        assertTrue(source.isDefault());
    }
}
