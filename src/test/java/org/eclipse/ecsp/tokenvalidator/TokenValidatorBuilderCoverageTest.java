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

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.eclipse.ecsp.tokenvalidator.impl.DefaultPublicKeyManager;
import org.eclipse.ecsp.tokenvalidator.impl.InMemoryPublicKeyCache;
import org.eclipse.ecsp.tokenvalidator.impl.NoFallbackStrategy;
import org.eclipse.ecsp.tokenvalidator.impl.StandardIssuerValidator;
import org.eclipse.ecsp.tokenvalidator.impl.WhitelistAlgorithmValidator;
import org.eclipse.ecsp.tokenvalidator.metrics.TokenValidatorMetricsConfig;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

/**
 * Additional coverage tests for {@link TokenValidatorBuilder}.
 *
 * @author Abhishek Kumar
 */
class TokenValidatorBuilderCoverageTest {

    private static final int RSA_KEY_SIZE = 2048;
    private static final int CACHE_CAPACITY = 100;

    private static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(RSA_KEY_SIZE);
        return gen.generateKeyPair();
    }

    private static PublicKeyManager buildManager(InMemoryPublicKeyCache cache) {
        return new DefaultPublicKeyManager(List.of(), List.of(), cache, new NoFallbackStrategy(), false);
    }

    @Test
    void buildWithoutPublicKeyManagerThrows() {
        TokenValidatorBuilder builder = TokenValidatorBuilder.builder();
        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    void buildWithCustomAlgorithmValidator() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .algorithmValidator(new WhitelistAlgorithmValidator(List.of("RS256")))
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithCustomIssuerValidator() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .issuerValidator(new StandardIssuerValidator(Set.of("iss")))
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithAudienceValidator() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        AudienceValidator audienceValidator = (aud, ki) -> {};
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .audienceValidator(audienceValidator)
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithCustomPreprocessorAndParser() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .preprocessor(mock(TokenPreprocessor.class))
            .tokenParser(mock(TokenParser.class))
            .signatureValidator(mock(TokenSignatureValidator.class))
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithCustomClaimsValidator() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .claimsValidator(mock(TokenClaimsValidator.class))
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithMetricsConfigEnabledButNoRegistryThrows() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        TokenValidatorMetricsConfig enabledConfig = TokenValidatorMetricsConfig.builder()
            .enabled(true)
            .build();
        TokenValidatorBuilder builder = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .metricsConfig(enabledConfig); // no meterRegistry()
        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    void buildWithMetricsConfigDisabledRequiresNoRegistry() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        TokenValidatorMetricsConfig disabledConfig = TokenValidatorMetricsConfig.builder()
            .enabled(false)
            .build();
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .metricsConfig(disabledConfig) // disabled — no registry needed
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithMetricsConfig() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        TokenValidatorMetricsConfig cfg = TokenValidatorMetricsConfig.builder()
            .prefix("my.service")
            .disableMetric(TokenValidatorMetricsConfig.KEY_CACHE_SIZE)
            .build();
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .metricsConfig(cfg)
            .meterRegistry(new SimpleMeterRegistry())
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithMeterRegistryAndNoExplicitConfig() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .meterRegistry(new SimpleMeterRegistry())
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithNullClockSkewDefaultsToZero() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .clockSkew(null)
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithKeySourcesDerviesIssuerAutomatically() {
        PublicKeySource src = new PublicKeySource();
        src.setIssuer("https://accounts.example.com");
        src.setUrl("https://accounts.example.com/.well-known/jwks.json");
        TokenValidator validator = TokenValidatorBuilder.builder()
            .keySources(List.of(src))
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithKeySourcesAndExplicitTrustedIssuers() {
        PublicKeySource src = new PublicKeySource();
        src.setIssuer("https://accounts.example.com");
        src.setUrl("https://accounts.example.com/.well-known/jwks.json");
        TokenValidator validator = TokenValidatorBuilder.builder()
            .keySources(List.of(src))
            .trustedIssuers(Set.of("https://accounts.example.com"))
            .build();
        assertNotNull(validator);
    }

    @Test
    void buildWithEmptyKeySourcesAndNoManagerThrows() {
        TokenValidatorBuilder builder = TokenValidatorBuilder.builder()
            .keySources(List.of());
        assertThrows(IllegalStateException.class, builder::build);
    }

    @Test
    void buildWithKeySourcesPublicKeyManagerTakesPrecedence() throws Exception {
        KeyPair kp = generateKeyPair();
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put("iss:kid1", new PublicKeyInfo(kp.getPublic(), "kid1", "iss", null));
        PublicKeySource src = new PublicKeySource();
        src.setIssuer("https://other.example.com");
        src.setUrl("https://other.example.com/.well-known/jwks.json");
        // publicKeyManager() should take precedence over keySources()
        TokenValidator validator = TokenValidatorBuilder.builder()
            .publicKeyManager(buildManager(cache))
            .keySources(List.of(src))
            .build();
        assertNotNull(validator);
    }
}
