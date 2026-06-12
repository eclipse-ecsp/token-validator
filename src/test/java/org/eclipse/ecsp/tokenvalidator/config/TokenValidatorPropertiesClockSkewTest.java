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

package org.eclipse.ecsp.tokenvalidator.config;

import org.junit.jupiter.api.Test;
import java.time.Duration;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Unit tests for clock-skew capping and validation in {@link TokenValidatorProperties}.
 *
 * @author Abhishek Kumar
 */
class TokenValidatorPropertiesClockSkewTest {

    private static final long THIRTY_SECONDS = 30L;
    private static final int FIVE_MINUTES = 5;
    private static final long NEGATIVE_ONE_SECOND = -1L;

    @Test
    void setClockSkewNullDefaultsToZero() {
        TokenValidatorProperties props = new TokenValidatorProperties();
        props.setClockSkew(null);
        assertEquals(Duration.ZERO, props.getClockSkew());
    }

    @Test
    void setClockSkewBelowMaxIsStoredAsIs() {
        TokenValidatorProperties props = new TokenValidatorProperties();
        Duration thirtySeconds = Duration.ofSeconds(THIRTY_SECONDS);
        props.setClockSkew(thirtySeconds);
        assertEquals(thirtySeconds, props.getClockSkew());
    }

    @Test
    void setClockSkewExactlyAtMaxIsAccepted() {
        TokenValidatorProperties props = new TokenValidatorProperties();
        props.setClockSkew(TokenValidatorProperties.MAX_CLOCK_SKEW);
        assertEquals(TokenValidatorProperties.MAX_CLOCK_SKEW, props.getClockSkew());
    }

    @Test
    void setClockSkewAboveMaxThrowsIllegalArgumentException() {
        TokenValidatorProperties props = new TokenValidatorProperties();
        assertThrows(IllegalArgumentException.class,
            () -> props.setClockSkew(Duration.ofMinutes(FIVE_MINUTES)));
    }

    @Test
    void setClockSkewNegativeThrowsIllegalArgumentException() {
        TokenValidatorProperties props = new TokenValidatorProperties();
        assertThrows(IllegalArgumentException.class,
            () -> props.setClockSkew(Duration.ofSeconds(NEGATIVE_ONE_SECOND)));
    }
}
