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

package org.eclipse.ecsp.tokenvalidator;

/**
 * Controls how required scopes are matched against the token's scope set.
 *
 * <p>Use {@link #ALL} to require every listed scope (conjunction); use {@link #ANY} to accept
 * tokens that carry at least one of the listed scopes (disjunction).
 *
 * @author Abhishek Kumar
 */
public enum ScopeMatchMode {

    /**
     * All required scopes must be present in the token (default, strictest mode).
     *
     * <p>Validation fails if even one required scope is absent from the token.
     */
    ALL,

    /**
     * At least one required scope must be present in the token.
     *
     * <p>Validation passes as soon as any single required scope is found in the token.
     * Validation fails only when none of the required scopes are present.
     */
    ANY
}
