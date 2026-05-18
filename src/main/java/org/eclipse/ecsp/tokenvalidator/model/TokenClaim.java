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

package org.eclipse.ecsp.tokenvalidator.model;

/**
 * Represents a single verified claim from a validated JWT token.
 *
 * <p>Callers interact with TokenClaim objects on every successful validation.
 * Provides both raw object access and typed access via {@link #getValue(Class)}.
 *
 * @author Abhishek Kumar
 */
public class TokenClaim {

    private final String name;
    private final Object value;

    /**
     * Constructs a TokenClaim with the given name and value.
     *
     * @param name  the claim name (e.g. "sub", "exp", "iss")
     * @param value the raw claim value
     */
    public TokenClaim(String name, Object value) {
        this.name = name;
        this.value = value;
    }

    /**
     * Returns the claim name.
     *
     * @return the claim name
     */
    public String getName() {
        return name;
    }

    /**
     * Returns the raw claim value as an Object.
     *
     * @return the raw claim value
     */
    public Object getValue() {
        return value;
    }

    /**
     * Returns the claim value cast to the requested type.
     *
     * <p>Uses {@link Class#cast(Object)} to perform a checked cast. If the stored
     * value type does not match the requested type, a {@link ClassCastException}
     * is thrown immediately. Guard with {@code instanceof} or catch
     * {@link ClassCastException} where the claim type cannot be guaranteed.
     *
     * @param <T>  the target type
     * @param type the Class to cast to
     * @return the value cast to T
     * @throws ClassCastException if the stored value is not assignable to type
     */
    public <T> T getValue(Class<T> type) {
        return type.cast(value);
    }

    @Override
    public String toString() {
        return "TokenClaim{name='" + name + "'}";
    }
}
