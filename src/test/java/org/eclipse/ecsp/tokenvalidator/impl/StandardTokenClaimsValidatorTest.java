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
import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidIssuerException;
import org.eclipse.ecsp.tokenvalidator.exception.TokenExpiredException;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import org.junit.jupiter.api.Test;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.function.Function;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link StandardTokenClaimsValidator}.
 *
 * @author Abhishek Kumar
 */
class StandardTokenClaimsValidatorTest {

    private static final long TOKEN_LIFETIME_SECONDS = 3600L;
    private static final long FUTURE_NBF_SECONDS = 600L;
    private static final long PAST_NBF_SECONDS = 60L;
    private static final long CLOCK_SKEW_SECONDS = 30L;
    private static final long SLIGHT_PAST_SECONDS = 20L;

    private final IssuerValidator issuerValidator = mock(IssuerValidator.class);
    private final AudienceValidator audienceValidator = mock(AudienceValidator.class);

    private List<TokenClaim> claimsWithExp(Instant expiry) {
        List<TokenClaim> claims = new ArrayList<>();
        claims.add(new TokenClaim("exp", Date.from(expiry)));
        claims.add(new TokenClaim("iss", "https://issuer.example.com"));
        return claims;
    }

    private List<TokenClaim> claimsWithExpAndNbf(Instant expiry, Instant nbf) {
        List<TokenClaim> claims = new ArrayList<>(claimsWithExp(expiry));
        claims.add(new TokenClaim("nbf", Date.from(nbf)));
        return claims;
    }

    @Test
    void validClaimsPass() {
        StandardTokenClaimsValidator validator = StandardTokenClaimsValidator.of(
            Duration.ZERO, issuerValidator, audienceValidator, java.util.Optional.empty());
        List<TokenClaim> claims = claimsWithExp(Instant.now().plusSeconds(TOKEN_LIFETIME_SECONDS));
        assertDoesNotThrow(() -> validator.validate(claims));
    }

    @Test
    void expiredTokenThrows() {
        StandardTokenClaimsValidator validator = StandardTokenClaimsValidator.of(
            Duration.ZERO, issuerValidator, audienceValidator, java.util.Optional.empty());
        List<TokenClaim> claims = claimsWithExp(Instant.now().minusSeconds(TOKEN_LIFETIME_SECONDS));
        assertThrows(TokenExpiredException.class, () -> validator.validate(claims));
    }

    @Test
    void notYetValidThrows() {
        StandardTokenClaimsValidator validator = StandardTokenClaimsValidator.of(
            Duration.ZERO, issuerValidator, audienceValidator, java.util.Optional.empty());
        List<TokenClaim> claims = claimsWithExpAndNbf(
            Instant.now().plusSeconds(TOKEN_LIFETIME_SECONDS), Instant.now().plusSeconds(FUTURE_NBF_SECONDS));
        assertThrows(InvalidClaimException.class, () -> validator.validate(claims));
    }

    @Test
    void nbfInPastPasses() {
        StandardTokenClaimsValidator validator = StandardTokenClaimsValidator.of(
            Duration.ZERO, issuerValidator, audienceValidator, java.util.Optional.empty());
        List<TokenClaim> claims = claimsWithExpAndNbf(
            Instant.now().plusSeconds(TOKEN_LIFETIME_SECONDS), Instant.now().minusSeconds(PAST_NBF_SECONDS));
        assertDoesNotThrow(() -> validator.validate(claims));
    }

    @Test
    void clockSkewAllowsSlightlyExpiredToken() {
        StandardTokenClaimsValidator validator = StandardTokenClaimsValidator.of(
            Duration.ofSeconds(CLOCK_SKEW_SECONDS), issuerValidator, audienceValidator, java.util.Optional.empty());
        List<TokenClaim> claims = claimsWithExp(Instant.now().minusSeconds(SLIGHT_PAST_SECONDS));
        assertDoesNotThrow(() -> validator.validate(claims));
    }

    @Test
    void invalidIssuerPropagates() {
        org.mockito.Mockito.doThrow(new InvalidIssuerException("bad issuer"))
            .when(issuerValidator).validate(org.mockito.ArgumentMatchers.anyString());
        StandardTokenClaimsValidator validator = StandardTokenClaimsValidator.of(
            Duration.ZERO, issuerValidator, audienceValidator, java.util.Optional.empty());
        List<TokenClaim> claims = claimsWithExp(Instant.now().plusSeconds(TOKEN_LIFETIME_SECONDS));
        assertThrows(InvalidIssuerException.class, () -> validator.validate(claims));
    }

    @Test
    void missingExpThrows() {
        StandardTokenClaimsValidator validator = StandardTokenClaimsValidator.of(
            Duration.ZERO, issuerValidator, audienceValidator, java.util.Optional.empty());
        List<TokenClaim> claims = List.of(new TokenClaim("iss", "https://issuer.example.com"));
        assertThrows(TokenExpiredException.class, () -> validator.validate(claims));
    }

    @Test
    void factoryMethodCreatesValidator() {
        Function<PublicKeyInfo, StandardTokenClaimsValidator> factory = StandardTokenClaimsValidator.factory(
            Duration.ZERO, issuerValidator, audienceValidator);
        PublicKeyInfo keyInfo = mock(PublicKeyInfo.class);
        when(keyInfo.getExpectedAudiences()).thenReturn(null);
        StandardTokenClaimsValidator validator = factory.apply(keyInfo);
        assertDoesNotThrow(() -> validator.validate(List.of(
            new TokenClaim("exp", Date.from(Instant.now().plusSeconds(TOKEN_LIFETIME_SECONDS))),
            new TokenClaim("iss", "iss"))));
    }
}
