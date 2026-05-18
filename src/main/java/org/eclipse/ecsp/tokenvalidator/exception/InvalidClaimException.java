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
 * Exception thrown when standard or custom claim validation fails.
 *
 * <p>This is the parent of {@link TokenExpiredException} and {@link InvalidIssuerException}.
 * It covers audience mismatch, missing required claims, and custom hook failures.
 * Catching this exception handles all claim-level validation failures.
 *
 * @author Abhishek Kumar
 */
public class InvalidClaimException extends TokenValidatorException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new InvalidClaimException with the specified detail message.
     *
     * @param message the detail message
     */
    public InvalidClaimException(String message) {
        super(message);
    }

    /**
     * Constructs a new InvalidClaimException with the specified message and cause.
     *
     * @param message the detail message
     * @param cause   the cause of the exception
     */
    public InvalidClaimException(String message, Throwable cause) {
        super(message, cause);
    }
}
