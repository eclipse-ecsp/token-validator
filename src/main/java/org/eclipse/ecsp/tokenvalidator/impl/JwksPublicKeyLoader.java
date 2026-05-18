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

package org.eclipse.ecsp.tokenvalidator.impl;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.eclipse.ecsp.tokenvalidator.JwksRetryStrategy;
import org.eclipse.ecsp.tokenvalidator.PublicKeyLoader;
import org.eclipse.ecsp.tokenvalidator.exception.KeyLoadException;
import org.eclipse.ecsp.tokenvalidator.metrics.NoopValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.metrics.ValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyType;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.io.IOException;
import java.net.URI;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Loads public keys from a JWKS endpoint using Apache HttpClient 5.
 *
 * <p>Parses the JWKS response with nimbus-jose-jwt {@link JWKSet}. Uses the configured
 * {@link JwksRetryStrategy} for retrying failed fetch attempts. Implements
 * {@link java.io.Closeable} for proper resource cleanup.
 *
 * @author Abhishek Kumar
 */
public class JwksPublicKeyLoader implements PublicKeyLoader {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(JwksPublicKeyLoader.class);

    /** Sentinel returned by {@link java.net.URI#getPort()} when no port is present. */
    private static final int URI_NO_PORT = -1;

    /** HTTP 200 OK status code expected from a healthy JWKS endpoint. */
    private static final int HTTP_OK = 200;

    /** Loopback host names and address that are exempt from HTTPS enforcement. */
    private static final java.util.Set<String> LOOPBACK_HOSTS =
        java.util.Set.of("localhost", "127.0.0.1", "[::1]", "0:0:0:0:0:0:0:1");

    private final JwksRetryStrategy retryStrategy;
    private final CloseableHttpClient httpClient;
    private final ValidationMetricsRecorder metricsRecorder;

    /**
     * Constructs a JwksPublicKeyLoader with the default retry strategy and HTTP client.
     */
    public JwksPublicKeyLoader() {
        this(new ExponentialBackoffJwksRetryStrategy(), HttpClients.createDefault(),
            NoopValidationMetricsRecorder.INSTANCE);
    }

    /**
     * Constructs a JwksPublicKeyLoader with the given retry strategy.
     *
     * @param retryStrategy the retry strategy for JWKS fetch failures
     */
    public JwksPublicKeyLoader(JwksRetryStrategy retryStrategy) {
        this(retryStrategy, HttpClients.createDefault(), NoopValidationMetricsRecorder.INSTANCE);
    }

    /**
     * Constructs a JwksPublicKeyLoader with the given retry strategy and metrics recorder.
     *
     * @param retryStrategy   the retry strategy for JWKS fetch failures
     * @param metricsRecorder the metrics recorder for observability
     */
    public JwksPublicKeyLoader(JwksRetryStrategy retryStrategy,
                               ValidationMetricsRecorder metricsRecorder) {
        this(retryStrategy, HttpClients.createDefault(), metricsRecorder);
    }

    /**
     * Constructs a JwksPublicKeyLoader with the given retry strategy and HTTP client.
     *
     * @param retryStrategy the retry strategy for JWKS fetch failures
     * @param httpClient    the HTTP client to use for fetching JWKS
     */
    public JwksPublicKeyLoader(JwksRetryStrategy retryStrategy, CloseableHttpClient httpClient) {
        this(retryStrategy, httpClient, NoopValidationMetricsRecorder.INSTANCE);
    }

    /**
     * Constructs a JwksPublicKeyLoader with the given retry strategy, HTTP client, and metrics.
     *
     * @param retryStrategy   the retry strategy for JWKS fetch failures
     * @param httpClient      the HTTP client to use for fetching JWKS
     * @param metricsRecorder the metrics recorder for observability
     */
    public JwksPublicKeyLoader(JwksRetryStrategy retryStrategy,
                               CloseableHttpClient httpClient,
                               ValidationMetricsRecorder metricsRecorder) {
        this.retryStrategy = retryStrategy;
        this.httpClient = httpClient;
        this.metricsRecorder = metricsRecorder != null
            ? metricsRecorder : NoopValidationMetricsRecorder.INSTANCE;
    }

    /**
     * Loads public keys from the JWKS endpoint configured in the given source.
     *
     * @param config the public key source configuration containing the JWKS URL
     * @return map of key ID to public key
     * @throws RuntimeException if all retry attempts fail
     */
    @Override
    public Map<String, PublicKey> loadKeys(PublicKeySource config) {
        String url = config.getUrl();
        enforceHttps(url);
        String issuer = config.getIssuer();
        long startNanos = System.nanoTime();
        int attempt = 1;
        Exception lastException = null;
        while (true) {
            try {
                Map<String, PublicKey> keys = fetchJwks(url);
                metricsRecorder.recordJwksFetch(issuer, true, System.nanoTime() - startNanos);
                return keys;
            } catch (Exception ex) {
                lastException = ex;
                LOGGER.warn("JWKS fetch attempt {} failed for url={}: {}",
                    attempt, sanitizeUrlForLog(url), ex.getMessage());
                Optional<Duration> waitDuration = retryStrategy.decideRetry(attempt, ex);
                if (waitDuration.isEmpty()) {
                    break;
                }
                sleepQuietly(waitDuration.get());
                attempt++;
            }
        }
        metricsRecorder.recordJwksFetch(issuer, false, System.nanoTime() - startNanos);
        LOGGER.error("JWKS fetch exhausted all retries for url={}", sanitizeUrlForLog(url));
        throw new KeyLoadException("Failed to fetch JWKS from " + url
            + " after " + attempt + " attempts", lastException);
    }

    /**
     * Enforces that the JWKS URL uses HTTPS. Loopback addresses ({@code localhost},
     * {@code 127.0.0.1}, {@code [::1]}) are exempt to allow local testing.
     *
     * @param url the JWKS URL to validate
     * @throws KeyLoadException if the URL uses plain HTTP and is not a loopback address
     */
    private void enforceHttps(String url) {
        if (url == null || url.isBlank()) {
            return;
        }
        if (url.startsWith("https://")) {
            return;
        }
        try {
            URI uri = URI.create(url);
            String host = uri.getHost();
            if (host != null && LOOPBACK_HOSTS.contains(host.toLowerCase(java.util.Locale.ROOT))) {
                return;
            }
        } catch (Exception _) {
            // fall through to rejection
        }
        throw new KeyLoadException(
            "JWKS URL must use HTTPS for security. Received: " + sanitizeUrlForLog(url));
    }

    private Map<String, PublicKey> fetchJwks(String url) throws IOException {
        HttpGet request = new HttpGet(url);
        return httpClient.execute(request, response -> {
            int statusCode = response.getCode();
            if (statusCode != HTTP_OK) {
                throw new IOException("JWKS endpoint returned HTTP " + statusCode
                    + " for url=" + url);
            }
            String body = EntityUtils.toString(response.getEntity());
            try {
                return parseJwks(body);
            } catch (Exception ex) {
                throw new IOException("Failed to parse JWKS response: " + ex.getMessage(), ex);
            }
        });
    }

    private Map<String, PublicKey> parseJwks(String body) throws ParseException {
        JWKSet jwkSet = JWKSet.parse(body);
        Map<String, PublicKey> keys = new HashMap<>();
        for (JWK jwk : jwkSet.getKeys()) {
            try {
                PublicKey publicKey = jwk.toRSAKey().toPublicKey();
                keys.put(jwk.getKeyID(), publicKey);
            } catch (Exception _) {
                try {
                    PublicKey publicKey = jwk.toECKey().toPublicKey();
                    keys.put(jwk.getKeyID(), publicKey);
                } catch (Exception _) {
                    LOGGER.warn("Skipping unrecognised JWK type for kid={}", jwk.getKeyID());
                }
            }
        }
        LOGGER.info("JWKS loaded successfully: {} keys", keys.size());
        return keys;
    }

    private String sanitizeUrlForLog(String url) {
        try {
            URI uri = URI.create(url);
            String host = uri.getHost() != null ? uri.getHost() : "[unknown-host]";
            String portPart = uri.getPort() != URI_NO_PORT ? ":" + uri.getPort() : "";
            return uri.getScheme() + "://" + host + portPart + "[...]";
        } catch (Exception _) {
            return "[url-redacted]";
        }
    }

    private void sleepQuietly(Duration duration) {
        try {
            Thread.sleep(duration.toMillis());
        } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Returns the type of public key source this loader supports.
     *
     * @return {@link PublicKeyType#JWKS}
     */
    @Override
    public PublicKeyType getType() {
        return PublicKeyType.JWKS;
    }

    /**
     * Closes the underlying HTTP client.
     *
     * @throws IOException if an I/O error occurs during close
     */
    @Override
    public void close() throws IOException {
        httpClient.close();
    }
}
