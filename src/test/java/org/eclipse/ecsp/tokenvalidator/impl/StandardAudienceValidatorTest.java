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

import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link StandardAudienceValidator}.
 *
 * @author Abhishek Kumar
 */
class StandardAudienceValidatorTest {

    private final StandardAudienceValidator validator = new StandardAudienceValidator();

    @Test
    void nullExpectedAudienceSkipsValidation() {
        PublicKeyInfo keyInfo = mock(PublicKeyInfo.class);
        when(keyInfo.getExpectedAudience()).thenReturn(null);
        assertDoesNotThrow(() -> validator.validate("any-aud", keyInfo));
    }

    @Test
    void stringAudienceMatchesPasses() {
        PublicKeyInfo keyInfo = mock(PublicKeyInfo.class);
        when(keyInfo.getExpectedAudience()).thenReturn("myapi");
        assertDoesNotThrow(() -> validator.validate("myapi", keyInfo));
    }

    @Test
    void stringAudienceMismatchThrows() {
        PublicKeyInfo keyInfo = mock(PublicKeyInfo.class);
        when(keyInfo.getExpectedAudience()).thenReturn("myapi");
        assertThrows(InvalidClaimException.class, () -> validator.validate("other", keyInfo));
    }

    @Test
    void listAudienceMatchesPasses() {
        PublicKeyInfo keyInfo = mock(PublicKeyInfo.class);
        when(keyInfo.getExpectedAudience()).thenReturn("myapi");
        assertDoesNotThrow(() -> validator.validate(List.of("other", "myapi"), keyInfo));
    }

    @Test
    void listAudienceMismatchThrows() {
        PublicKeyInfo keyInfo = mock(PublicKeyInfo.class);
        when(keyInfo.getExpectedAudience()).thenReturn("myapi");
        List<String> audiences = List.of("a", "b");
        assertThrows(InvalidClaimException.class, () -> validator.validate(audiences, keyInfo));
    }

    @Test
    void nullTokenAudienceThrows() {
        PublicKeyInfo keyInfo = mock(PublicKeyInfo.class);
        when(keyInfo.getExpectedAudience()).thenReturn("myapi");
        assertThrows(InvalidClaimException.class, () -> validator.validate(null, keyInfo));
    }
}
