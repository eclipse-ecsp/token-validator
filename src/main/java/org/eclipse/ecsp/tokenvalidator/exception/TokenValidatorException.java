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

/**
 * Base exception for all token validator failures.
 *
 * <p>All exceptions thrown by the token validation pipeline extend this class,
 * allowing callers to catch all validation failures with a single handler.
 *
 * @author Abhishek Kumar
 */
public class TokenValidatorException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new TokenValidatorException with the specified detail message.
     *
     * @param message the detail message
     */
    public TokenValidatorException(String message) {
        super(message);
    }

    /**
     * Constructs a new TokenValidatorException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause   the cause of the exception
     */
    public TokenValidatorException(String message, Throwable cause) {
        super(message, cause);
    }
}
