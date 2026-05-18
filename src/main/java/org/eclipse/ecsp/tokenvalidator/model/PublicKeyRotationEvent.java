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

import org.springframework.context.ApplicationEvent;

/**
 * Spring ApplicationEvent signalling that signing keys for a given issuer have rotated.
 *
 * <p>Published by {@code DefaultPublicKeyManager} or an external rotation system.
 * {@code DefaultPublicKeyManager} listens for this event via {@code @EventListener}
 * and triggers an asynchronous per-issuer JWKS refresh without waiting for the
 * next scheduled {@code refreshInterval}.
 *
 * <p>Spring dependency note: this class extends {@code ApplicationEvent} and therefore
 * requires {@code spring-context} on the compile classpath. Integrations that require
 * a Spring-free model layer should publish rotation signals via a custom mechanism
 * and translate to {@code PublicKeyManager.refreshPublicKeys(issuer)} directly.
 *
 * @author Abhishek Kumar
 */
public class PublicKeyRotationEvent extends ApplicationEvent {

    private static final long serialVersionUID = 1L;

    private final String issuer;

    /**
     * Constructs a PublicKeyRotationEvent for the given issuer.
     *
     * @param source the component that published this event
     * @param issuer the issuer whose keys have rotated
     */
    public PublicKeyRotationEvent(Object source, String issuer) {
        super(source);
        this.issuer = issuer;
    }

    /**
     * Returns the issuer whose keys have rotated.
     *
     * @return the issuer string
     */
    public String getIssuer() {
        return issuer;
    }
}
