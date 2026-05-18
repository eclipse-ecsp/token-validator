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

package org.eclipse.ecsp.tokenvalidator.config;

/**
 * Centralised repository of Spring property-name constants for the token validator library.
 *
 * <p>Every property key or prefix used by {@link TokenValidatorProperties},
 * {@link OnTokenValidatorSourcesConfigured}, and related configuration classes is
 * declared here as a {@code public static final String}. Changing a property name in
 * one place automatically propagates to all usages.
 *
 * <p>These are compile-time string constants and may safely be referenced from
 * annotation parameters such as {@link org.springframework.boot.context.properties.ConfigurationProperties}.
 *
 * @author Abhishek Kumar
 */
public final class TokenValidatorPropertyNames {

    /**
     * Root prefix for all token-validator configuration properties
     * (i.e. {@code token.validator}).
     */
    public static final String PROPERTY_PREFIX = "token.validator";

    /**
     * Fully-qualified property path for the key-sources list
     * (i.e. {@code token.validator.sources}).
     */
    public static final String SOURCES_PROPERTY = PROPERTY_PREFIX + ".sources";

    private TokenValidatorPropertyNames() {
        // utility class — not instantiable
    }
}
