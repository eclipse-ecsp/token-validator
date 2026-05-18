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

import org.eclipse.ecsp.tokenvalidator.AudienceValidator;
import org.eclipse.ecsp.tokenvalidator.IssuerValidator;
import org.eclipse.ecsp.tokenvalidator.JwtTestUtil;
import org.eclipse.ecsp.tokenvalidator.PublicKeyManager;
import org.eclipse.ecsp.tokenvalidator.TokenClaimsValidator;
import org.eclipse.ecsp.tokenvalidator.ValidationHook;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidSignatureException;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidTokenException;
import org.eclipse.ecsp.tokenvalidator.exception.KeyNotFoundException;
import org.eclipse.ecsp.tokenvalidator.exception.TokenExpiredException;
import org.eclipse.ecsp.tokenvalidator.exception.UnsupportedTokenTypeException;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultTokenValidator}.
 *
 * @author Abhishek Kumar
 */
class DefaultTokenValidatorTest {

    private static final int CACHE_CAPACITY = 100;
    private static final long TOKEN_LIFETIME_SECONDS = 3600L;
    private static final int HOOK_ORDER_HIGH = 2;
    private static final int CONCURRENT_THREADS = 10;

    private static KeyPair keyPair;
    private static final String ISSUER = "https://issuer.example.com";
    private static final String KID = "testKey";

    @BeforeAll
    static void setUp() {
        keyPair = JwtTestUtil.generateRsaKeyPair();
    }

    private DefaultTokenValidator buildValidator(PublicKeyManager keyManager) {
        IssuerValidator issuerValidator = issuer -> {};
        AudienceValidator audienceValidator = (aud, keyInfo) -> {};
        Function<PublicKeyInfo, TokenClaimsValidator> factory =
            ki -> StandardTokenClaimsValidator.of(
                Duration.ZERO, issuerValidator, audienceValidator, Optional.of(ki));
        DefaultTokenValidator.Pipeline pipeline = new DefaultTokenValidator.Pipeline(
            new StandardTokenPreprocessor(),
            new StandardTokenParser(),
            new WhitelistAlgorithmValidator(List.of("RS256", "ES256")),
            new NimbusTokenSignatureValidator(),
            factory,
            List.of());
        return new DefaultTokenValidator(pipeline, keyManager);
    }

    private PublicKeyManager buildKeyManager() {
        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put(ISSUER + ":" + KID,
            new PublicKeyInfo(keyPair.getPublic(), KID, ISSUER, null));
        return new DefaultPublicKeyManager(
            List.of(), List.of(), cache, new NoFallbackStrategy(), false);
    }

    @Test
    void validateValidToken() throws Exception {
        String jwt = JwtTestUtil.createSignedJwt(KID, ISSUER, "user1", TOKEN_LIFETIME_SECONDS, keyPair.getPrivate());
        DefaultTokenValidator validator = buildValidator(buildKeyManager());
        List<TokenClaim> claims = validator.validate(jwt);
        assertNotNull(claims);
    }

    @Test
    void validateBearerPrefixStripped() throws Exception {
        String jwt = JwtTestUtil.createSignedJwt(KID, ISSUER, "user1", TOKEN_LIFETIME_SECONDS, keyPair.getPrivate());
        DefaultTokenValidator validator = buildValidator(buildKeyManager());
        List<TokenClaim> claims = validator.validate("Bearer " + jwt);
        assertNotNull(claims);
    }

    @Test
    void validateExpiredTokenThrows() {
        String jwt = JwtTestUtil.createExpiredJwt(KID, ISSUER, keyPair.getPrivate());
        DefaultTokenValidator validator = buildValidator(buildKeyManager());
        assertThrows(TokenExpiredException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateKeyNotFoundThrows() {
        PublicKeyManager keyManager = mock(PublicKeyManager.class);
        when(keyManager.findPublicKey(anyString(), anyString())).thenReturn(Optional.empty());
        DefaultTokenValidator validator = buildValidator(keyManager);
        String jwt = JwtTestUtil.createSignedJwt(KID, ISSUER, "user1", TOKEN_LIFETIME_SECONDS, keyPair.getPrivate());
        assertThrows(KeyNotFoundException.class, () -> validator.validate(jwt));
    }

    @Test
    void validateJweThrows() {
        DefaultTokenValidator validator = buildValidator(buildKeyManager());
        String fakeJwe = JwtTestUtil.createFakeJweToken();
        assertThrows(UnsupportedTokenTypeException.class, () -> validator.validate(fakeJwe));
    }

    @Test
    void validateNullThrows() {
        DefaultTokenValidator validator = buildValidator(buildKeyManager());
        assertThrows(InvalidTokenException.class, () -> validator.validate(null));
    }

    @Test
    void hookOrderedByGetOrder() throws Exception {
        List<Integer> callOrder = new ArrayList<>();

        ValidationHook hook1 = new ValidationHook() {
            @Override
            public void validate(List<TokenClaim> claims) throws InvalidClaimException {
                callOrder.add(HOOK_ORDER_HIGH);
            }

            @Override
            public int getOrder() {
                return HOOK_ORDER_HIGH;
            }
        };

        ValidationHook hook2 = new ValidationHook() {
            @Override
            public void validate(List<TokenClaim> claims) throws InvalidClaimException {
                callOrder.add(1);
            }

            @Override
            public int getOrder() {
                return 1;
            }
        };

        InMemoryPublicKeyCache cache = new InMemoryPublicKeyCache(CACHE_CAPACITY);
        cache.put(ISSUER + ":" + KID, new PublicKeyInfo(keyPair.getPublic(), KID, ISSUER, null));
        PublicKeyManager keyManager = new DefaultPublicKeyManager(
            List.of(), List.of(), cache, new NoFallbackStrategy(), false);

        IssuerValidator issuerValidator = iss -> {};
        AudienceValidator audienceValidator = (aud, ki) -> {};
        Function<PublicKeyInfo, TokenClaimsValidator> hookFactory =
            ki -> StandardTokenClaimsValidator.of(
                Duration.ZERO, issuerValidator, audienceValidator, Optional.of(ki));
        DefaultTokenValidator.Pipeline pipeline = new DefaultTokenValidator.Pipeline(
            new StandardTokenPreprocessor(),
            new StandardTokenParser(),
            new WhitelistAlgorithmValidator(List.of("RS256")),
            new NimbusTokenSignatureValidator(),
            hookFactory,
            List.of(hook1, hook2));
        DefaultTokenValidator validator = new DefaultTokenValidator(pipeline, keyManager);

        String jwt = JwtTestUtil.createSignedJwt(KID, ISSUER, "user1", TOKEN_LIFETIME_SECONDS, keyPair.getPrivate());
        validator.validate(jwt);
        assertNotNull(callOrder);
        assert callOrder.get(0) == 1;
        assert callOrder.get(1) == HOOK_ORDER_HIGH;
    }

    @Test
    void validateInvalidSignatureThrows() {
        // Sign with a different key pair than the one registered in cache
        KeyPair wrongKeyPair = JwtTestUtil.generateRsaKeyPair();
        String jwt = JwtTestUtil.createSignedJwt(KID, ISSUER, "user1",
            TOKEN_LIFETIME_SECONDS, wrongKeyPair.getPrivate());

        DefaultTokenValidator validator = buildValidator(buildKeyManager());
        assertThrows(InvalidSignatureException.class, () -> validator.validate(jwt));
    }

    @Test
    void nullHooksAndNullMetricsRecorderUseSafeDefaults() throws Exception {
        // Covers hooks == null and metricsRecorder == null constructor branches
        IssuerValidator issuerValidator = issuer -> {};
        AudienceValidator audienceValidator = (aud, keyInfo) -> {};
        Function<PublicKeyInfo, TokenClaimsValidator> factory =
            ki -> StandardTokenClaimsValidator.of(
                Duration.ZERO, issuerValidator, audienceValidator, Optional.of(ki));
        // null hooks → should default to empty list; null metricsRecorder → Noop
        DefaultTokenValidator.Pipeline pipeline = new DefaultTokenValidator.Pipeline(
            new StandardTokenPreprocessor(),
            new StandardTokenParser(),
            new WhitelistAlgorithmValidator(List.of("RS256", "ES256")),
            new NimbusTokenSignatureValidator(),
            factory,
            null);
        DefaultTokenValidator validator = new DefaultTokenValidator(pipeline, buildKeyManager(), null);
        String jwt = JwtTestUtil.createSignedJwt(KID, ISSUER, "user1",
            TOKEN_LIFETIME_SECONDS, keyPair.getPrivate());
        List<TokenClaim> claims = validator.validate(jwt);
        assertNotNull(claims);
    }

    @Test
    void concurrentValidationDoesNotThrow() throws Exception {
        DefaultTokenValidator validator = buildValidator(buildKeyManager());
        String jwt = JwtTestUtil.createSignedJwt(KID, ISSUER, "user1", TOKEN_LIFETIME_SECONDS, keyPair.getPrivate());
        List<Thread> threads = new ArrayList<>();
        List<Exception> errors = new ArrayList<>();
        for (int ii = 0; ii < CONCURRENT_THREADS; ii++) {
            threads.add(Thread.ofVirtual().start(() -> {
                try {
                    validator.validate(jwt);
                } catch (Exception ex) {
                    synchronized (errors) {
                        errors.add(ex);
                    }
                }
            }));
        }
        for (Thread thread : threads) {
            thread.join();
        }
        assert errors.isEmpty() : "Concurrent validation errors: " + errors;
    }
}
