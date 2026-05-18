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

package org.eclipse.ecsp.tokenvalidator.exception;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Tests for the exception hierarchy.
 *
 * @author Abhishek Kumar
 */
class ExceptionHierarchyTest {

    @Test
    void tokenValidatorExceptionIsRuntimeException() {
        TokenValidatorException ex = new TokenValidatorException("test");
        assertInstanceOf(RuntimeException.class, ex);
        assertEquals("test", ex.getMessage());
    }

    @Test
    void tokenValidatorExceptionWithCause() {
        Throwable cause = new IllegalStateException("cause");
        TokenValidatorException ex = new TokenValidatorException("msg", cause);
        assertEquals(cause, ex.getCause());
    }

    @Test
    void invalidTokenExceptionExtendsTokenValidatorException() {
        InvalidTokenException ex = new InvalidTokenException("invalid");
        assertInstanceOf(TokenValidatorException.class, ex);
    }

    @Test
    void malformedTokenExceptionExtendsInvalidTokenException() {
        MalformedTokenException ex = new MalformedTokenException("malformed");
        assertInstanceOf(InvalidTokenException.class, ex);
    }

    @Test
    void malformedTokenExceptionWithCause() {
        Throwable cause = new RuntimeException("cause");
        MalformedTokenException ex = new MalformedTokenException("msg", cause);
        assertEquals(cause, ex.getCause());
    }

    @Test
    void unsupportedTokenTypeExceptionExtendsInvalidTokenException() {
        UnsupportedTokenTypeException ex = new UnsupportedTokenTypeException("jwe");
        assertInstanceOf(InvalidTokenException.class, ex);
    }

    @Test
    void unsupportedTokenTypeExceptionWithCause() {
        Throwable cause = new RuntimeException("cause");
        UnsupportedTokenTypeException ex = new UnsupportedTokenTypeException("msg", cause);
        assertNotNull(ex);
    }

    @Test
    void invalidSignatureExceptionExtendsTokenValidatorException() {
        InvalidSignatureException ex = new InvalidSignatureException("sig fail");
        assertInstanceOf(TokenValidatorException.class, ex);
    }

    @Test
    void invalidSignatureExceptionWithCause() {
        Throwable cause = new RuntimeException("cause");
        InvalidSignatureException ex = new InvalidSignatureException("msg", cause);
        assertEquals(cause, ex.getCause());
    }

    @Test
    void keyNotFoundExceptionExtendsTokenValidatorException() {
        KeyNotFoundException ex = new KeyNotFoundException("no key");
        assertInstanceOf(TokenValidatorException.class, ex);
    }

    @Test
    void keyNotFoundExceptionWithCause() {
        Throwable cause = new RuntimeException("cause");
        KeyNotFoundException ex = new KeyNotFoundException("msg", cause);
        assertEquals(cause, ex.getCause());
    }

    @Test
    void unsupportedAlgorithmExceptionExtendsTokenValidatorException() {
        UnsupportedAlgorithmException ex = new UnsupportedAlgorithmException("none");
        assertInstanceOf(TokenValidatorException.class, ex);
    }

    @Test
    void unsupportedAlgorithmExceptionWithCause() {
        Throwable cause = new RuntimeException("cause");
        UnsupportedAlgorithmException ex = new UnsupportedAlgorithmException("msg", cause);
        assertEquals(cause, ex.getCause());
    }

    @Test
    void invalidClaimExceptionExtendsTokenValidatorException() {
        InvalidClaimException ex = new InvalidClaimException("claim fail");
        assertInstanceOf(TokenValidatorException.class, ex);
    }

    @Test
    void invalidClaimExceptionWithCause() {
        Throwable cause = new RuntimeException("cause");
        InvalidClaimException ex = new InvalidClaimException("msg", cause);
        assertEquals(cause, ex.getCause());
    }

    @Test
    void tokenExpiredExceptionExtendsInvalidClaimException() {
        TokenExpiredException ex = new TokenExpiredException("expired");
        assertInstanceOf(InvalidClaimException.class, ex);
    }

    @Test
    void tokenExpiredExceptionWithCause() {
        Throwable cause = new RuntimeException("cause");
        TokenExpiredException ex = new TokenExpiredException("msg", cause);
        assertEquals(cause, ex.getCause());
    }

    @Test
    void invalidIssuerExceptionExtendsInvalidClaimException() {
        InvalidIssuerException ex = new InvalidIssuerException("bad issuer");
        assertInstanceOf(InvalidClaimException.class, ex);
    }

    @Test
    void invalidIssuerExceptionWithCause() {
        Throwable cause = new RuntimeException("cause");
        InvalidIssuerException ex = new InvalidIssuerException("msg", cause);
        assertEquals(cause, ex.getCause());
    }
}
