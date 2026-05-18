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
 * Exception thrown when the JWT token's expiration claim is in the past.
 *
 * <p>This exception is thrown when the {@code exp} claim is in the past beyond
 * the configured clock-skew tolerance. It is a subtype of {@link InvalidClaimException}.
 *
 * @author Abhishek Kumar
 */
public class TokenExpiredException extends InvalidClaimException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new TokenExpiredException with the specified detail message.
     *
     * @param message the detail message
     */
    public TokenExpiredException(String message) {
        super(message);
    }

    /**
     * Constructs a new TokenExpiredException with the specified message and cause.
     *
     * @param message the detail message
     * @param cause   the cause of the exception
     */
    public TokenExpiredException(String message, Throwable cause) {
        super(message, cause);
    }
}
