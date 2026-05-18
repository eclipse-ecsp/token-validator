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

import org.eclipse.ecsp.tokenvalidator.exception.InvalidTokenException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link StandardTokenPreprocessor}.
 *
 * @author Abhishek Kumar
 */
class StandardTokenPreprocessorTest {

    private final StandardTokenPreprocessor preprocessor = new StandardTokenPreprocessor();

    @Test
    void preprocessStripsBearer() {
        String result = preprocessor.preprocess("Bearer mytoken");
        assertEquals("mytoken", result);
    }

    @Test
    void preprocessStripsLowercaseBearer() {
        String result = preprocessor.preprocess("bearer mytoken");
        assertEquals("mytoken", result);
    }

    @Test
    void preprocessTrimsSurroundingWhitespace() {
        String result = preprocessor.preprocess("  mytoken  ");
        assertEquals("mytoken", result);
    }

    @Test
    void preprocessNoBearer() {
        String result = preprocessor.preprocess("rawtoken");
        assertEquals("rawtoken", result);
    }

    @Test
    void preprocessNullThrows() {
        assertThrows(InvalidTokenException.class, () -> preprocessor.preprocess(null));
    }

    @Test
    void preprocessBlankThrows() {
        assertThrows(InvalidTokenException.class, () -> preprocessor.preprocess("   "));
    }

    @Test
    void preprocessBearerOnlyTreatedAsToken() {
        // "Bearer " trims to "Bearer" which has no prefix match, so it's returned as-is
        String result = preprocessor.preprocess("Bearer ");
        assertEquals("Bearer", result);
    }

    @Test
    void preprocessBearerWithExtraSpaces() {
        String result = preprocessor.preprocess("Bearer   mytoken  ");
        assertEquals("mytoken", result);
    }
}
