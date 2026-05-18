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

import java.util.List;

/**
 * Extracts the scopes required by an API route from its configuration context.
 *
 * <p>No default implementation is provided in the core library; each integration
 * supplies its own implementation.
 *
 * @param <C> the type of route/API configuration context
 * @author Abhishek Kumar
 */
public interface ApiScopeExtractor<C> {

    /**
     * Returns the list of scopes required by the given API context.
     *
     * @param context route or API configuration (e.g. JwtAuthFilter.Config)
     * @return list of required scope strings
     */
    List<String> extractRequiredScopes(C context);
}
