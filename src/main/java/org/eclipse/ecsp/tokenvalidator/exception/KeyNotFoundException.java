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
 * Exception thrown when no public key is found for the given issuer and key ID.
 *
 * <p>This exception is thrown when the public key cache does not contain a key
 * for the specified issuer and kid, and the fallback strategy also fails to
 * resolve a key.
 *
 * @author Abhishek Kumar
 */
public class KeyNotFoundException extends TokenValidatorException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new KeyNotFoundException with the specified detail message.
     *
     * @param message the detail message
     */
    public KeyNotFoundException(String message) {
        super(message);
    }

    /**
     * Constructs a new KeyNotFoundException with the specified message and cause.
     *
     * @param message the detail message
     * @param cause   the cause of the exception
     */
    public KeyNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
