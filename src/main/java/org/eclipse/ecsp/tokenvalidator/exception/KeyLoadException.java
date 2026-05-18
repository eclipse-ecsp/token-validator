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
 * Exception thrown when loading a public key from a JWKS endpoint or PEM file fails.
 *
 * <p>Wraps I/O errors, HTTP failures, and key-parse errors so callers can
 * distinguish key-load failures from other runtime errors without catching
 * the raw {@link RuntimeException}.
 *
 * @author Abhishek Kumar
 */
public class KeyLoadException extends TokenValidatorException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new KeyLoadException with the specified detail message.
     *
     * @param message the detail message
     */
    public KeyLoadException(String message) {
        super(message);
    }

    /**
     * Constructs a new KeyLoadException with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause   the cause of the exception
     */
    public KeyLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}
