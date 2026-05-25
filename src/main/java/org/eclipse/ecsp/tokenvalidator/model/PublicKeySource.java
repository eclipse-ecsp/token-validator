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

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Configuration object describing one key source for a single issuer.
 *
 * <p>Must be treated as effectively immutable after being passed to
 * {@code DefaultPublicKeyManager}. Mutations after manager construction
 * create data races on the validation hot path.
 *
 * @author Abhishek Kumar
 */
public class PublicKeySource {

    private String id;
    private String issuer;
    private String url;
    private String location;
    private Duration refreshInterval;
    private List<String> audiences = new ArrayList<>();
    private boolean isDefault;

    /**
     * Constructs a new empty PublicKeySource.
     */
    public PublicKeySource() {
        // No-args constructor required for Spring configuration-property binding
    }

    /**
     * Returns the unique source identifier.
     *
     * @return the source ID
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the unique source identifier.
     *
     * @param id the source ID
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Returns the expected issuer claim value.
     *
     * @return the issuer string
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Sets the expected issuer claim value.
     *
     * @param issuer the issuer string
     */
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    /**
     * Returns the JWKS endpoint URL (mutually exclusive with {@link #getLocation()}).
     *
     * @return the JWKS URL, or null if this is a PEM source
     */
    public String getUrl() {
        return url;
    }

    /**
     * Sets the JWKS endpoint URL.
     *
     * @param url the JWKS URL
     */
    public void setUrl(String url) {
        this.url = url;
    }

    /**
     * Returns the file-system path to a PEM public key (mutually exclusive with {@link #getUrl()}).
     *
     * @return the PEM file location, or null if this is a JWKS source
     */
    public String getLocation() {
        return location;
    }

    /**
     * Sets the file-system path to a PEM public key.
     *
     * @param location the PEM file path
     */
    public void setLocation(String location) {
        this.location = location;
    }

    /**
     * Returns the refresh interval for scheduled JWKS re-fetches.
     *
     * @return the refresh interval duration
     */
    public Duration getRefreshInterval() {
        return refreshInterval;
    }

    /**
     * Sets the refresh interval for scheduled JWKS re-fetches.
     *
     * @param refreshInterval the refresh interval duration
     */
    public void setRefreshInterval(Duration refreshInterval) {
        this.refreshInterval = refreshInterval;
    }

    /**
     * Returns the list of accepted audience values for per-issuer audience validation.
     *
     * <p>A token is accepted when its {@code aud} claim contains at least one value
     * from this list. Returns an empty list (never {@code null}) when audience
     * validation is not configured for this source.
     *
     * @return the list of accepted audience values; empty means skip aud validation
     */
    public List<String> getAudiences() {
        return audiences;
    }

    /**
     * Sets the list of accepted audience values.
     *
     * @param audiences the list of accepted audience values
     */
    public void setAudiences(List<String> audiences) {
        this.audiences = audiences;
    }

    /**
     * Returns whether this source is the default key for its issuer.
     *
     * @return true if this is the issuer's default key source
     */
    public boolean isDefault() {
        return isDefault;
    }

    /**
     * Sets whether this source is the default key for its issuer.
     *
     * @param defaultSource true if this is the issuer's default key source
     */
    public void setDefault(boolean defaultSource) {
        this.isDefault = defaultSource;
    }

    /**
     * Returns the resolved {@link PublicKeyType} based on configured fields.
     *
     * @return {@link PublicKeyType#JWKS} if url is set, {@link PublicKeyType#PEM} if location is set
     */
    public PublicKeyType getType() {
        if (url != null && !url.isBlank()) {
            return PublicKeyType.JWKS;
        }
        return PublicKeyType.PEM;
    }
}
