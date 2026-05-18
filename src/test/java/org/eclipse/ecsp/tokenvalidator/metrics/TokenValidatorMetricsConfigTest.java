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

package org.eclipse.ecsp.tokenvalidator.metrics;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link TokenValidatorMetricsConfig}.
 *
 * @author Abhishek Kumar
 */
class TokenValidatorMetricsConfigTest {

    @Test
    void isEnabledReturnsTrue() {
        TokenValidatorMetricsConfig config = TokenValidatorMetricsConfig.builder()
            .enabled(true)
            .prefix("token.validator")
            .build();
        assertTrue(config.isEnabled());
    }

    @Test
    void isEnabledReturnsFalse() {
        TokenValidatorMetricsConfig config = TokenValidatorMetricsConfig.builder()
            .enabled(false)
            .prefix("token.validator")
            .build();
        assertFalse(config.isEnabled());
    }

    @Test
    void getMetricNameUsesPrefix() {
        TokenValidatorMetricsConfig config = TokenValidatorMetricsConfig.builder()
            .enabled(true)
            .prefix("myapp")
            .build();
        String name = config.getMetricName(TokenValidatorMetricsConfig.KEY_VALIDATIONS);
        assertNotNull(name);
        assertTrue(name.startsWith("myapp"));
    }

    @Test
    void getMetricNameUsesCustomName() {
        TokenValidatorMetricsConfig config = TokenValidatorMetricsConfig.builder()
            .enabled(true)
            .prefix("myapp")
            .metricName(TokenValidatorMetricsConfig.KEY_VALIDATIONS, "my.custom.metric")
            .build();
        String name = config.getMetricName(TokenValidatorMetricsConfig.KEY_VALIDATIONS);
        assertTrue(name.contains("my.custom.metric"));
    }

    @Test
    void isDisabledWhenNotEnabled() {
        TokenValidatorMetricsConfig config = TokenValidatorMetricsConfig.builder()
            .enabled(false)
            .prefix("myapp")
            .build();
        assertTrue(config.isDisabled(TokenValidatorMetricsConfig.KEY_VALIDATIONS));
    }

    @Test
    void isDisabledWhenInDisabledList() {
        TokenValidatorMetricsConfig config = TokenValidatorMetricsConfig.builder()
            .enabled(true)
            .prefix("myapp")
            .disableMetric(TokenValidatorMetricsConfig.KEY_VALIDATIONS)
            .build();
        assertTrue(config.isDisabled(TokenValidatorMetricsConfig.KEY_VALIDATIONS));
    }

    @Test
    void isNotDisabledWhenEnabledAndNotInList() {
        TokenValidatorMetricsConfig config = TokenValidatorMetricsConfig.builder()
            .enabled(true)
            .prefix("myapp")
            .build();
        assertFalse(config.isDisabled(TokenValidatorMetricsConfig.KEY_VALIDATIONS));
    }

    @Test
    void getPrefix() {
        TokenValidatorMetricsConfig config = TokenValidatorMetricsConfig.builder()
            .enabled(true)
            .prefix("test.prefix")
            .build();
        assertEquals("test.prefix", config.getPrefix());
    }

    @Test
    void nullPrefixFallsBackToDefault() {
        TokenValidatorMetricsConfig config = TokenValidatorMetricsConfig.builder()
            .prefix(null)
            .build();
        assertEquals("token.validator", config.getPrefix());
    }
}
