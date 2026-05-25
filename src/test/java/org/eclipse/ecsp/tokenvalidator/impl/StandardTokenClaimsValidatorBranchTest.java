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

import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.exception.TokenExpiredException;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Date;
import java.util.List;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Additional branch coverage for {@link StandardTokenClaimsValidator}.
 *
 * @author Abhishek Kumar
 */
class StandardTokenClaimsValidatorBranchTest {

    private static final String ISSUER = "https://issuer.example.com";
    private static final int FAST_RSA_KEY_SIZE = 512;
    private static final long FUTURE_OFFSET_MS = 60000L;
    private static final long FAR_FUTURE_OFFSET_MS = 120000L;
    private static final long MS_PER_SECOND = 1000L;

    private List<TokenClaim> buildClaims(Object expValue) {
        // Helper — replaces or provides exp as Date object
        return List.of(
            new TokenClaim("iss", ISSUER),
            new TokenClaim("exp", expValue)
        );
    }

    @Test
    void expAsDateInFutureIsValid() {
        StandardIssuerValidator issuerValidator = new StandardIssuerValidator(Set.of(ISSUER));
        StandardTokenClaimsValidator validator = new StandardTokenClaimsValidator(
            Duration.ZERO, issuerValidator, null, null);

        Date future = new Date(System.currentTimeMillis() + FUTURE_OFFSET_MS);
        List<TokenClaim> claims = buildClaims(future);
        assertDoesNotThrow(() -> validator.validate(claims));
    }

    @Test
    void expAsDateInPastThrows() {
        StandardIssuerValidator issuerValidator = new StandardIssuerValidator(Set.of(ISSUER));
        StandardTokenClaimsValidator validator = new StandardTokenClaimsValidator(
            Duration.ZERO, issuerValidator, null, null);

        Date past = new Date(System.currentTimeMillis() - FUTURE_OFFSET_MS);
        List<TokenClaim> claims = buildClaims(past);
        assertThrows(TokenExpiredException.class, () -> validator.validate(claims));
    }

    @Test
    void expAsStringThrowsInvalidClaim() {
        StandardIssuerValidator issuerValidator = new StandardIssuerValidator(Set.of(ISSUER));
        StandardTokenClaimsValidator validator = new StandardTokenClaimsValidator(
            Duration.ZERO, issuerValidator, null, null);

        List<TokenClaim> claims = List.of(
            new TokenClaim("iss", ISSUER),
            new TokenClaim("exp", "not-a-number")
        );
        assertThrows(InvalidClaimException.class, () -> validator.validate(claims));
    }

    @Test
    void nbfAsDateNotYetValidThrows() {
        StandardIssuerValidator issuerValidator = new StandardIssuerValidator(Set.of(ISSUER));
        StandardTokenClaimsValidator validator = new StandardTokenClaimsValidator(
            Duration.ZERO, issuerValidator, null, null);

        Date future = new Date(System.currentTimeMillis() + FUTURE_OFFSET_MS);
        long futureEpoch = (System.currentTimeMillis() + FAR_FUTURE_OFFSET_MS) / MS_PER_SECOND;
        List<TokenClaim> claims = List.of(
            new TokenClaim("iss", ISSUER),
            new TokenClaim("exp", futureEpoch),
            new TokenClaim("nbf", future)
        );
        assertThrows(InvalidClaimException.class, () -> validator.validate(claims));
    }

    @Test
    void nbfInPastIsAccepted() {
        StandardIssuerValidator issuerValidator = new StandardIssuerValidator(Set.of(ISSUER));
        StandardTokenClaimsValidator validator = new StandardTokenClaimsValidator(
            Duration.ZERO, issuerValidator, null, null);

        Date pastNbf = new Date(System.currentTimeMillis() - FUTURE_OFFSET_MS);
        long futureEpoch = (System.currentTimeMillis() + FAR_FUTURE_OFFSET_MS) / MS_PER_SECOND;
        List<TokenClaim> claims = List.of(
            new TokenClaim("iss", ISSUER),
            new TokenClaim("exp", futureEpoch),
            new TokenClaim("nbf", pastNbf)
        );
        assertDoesNotThrow(() -> validator.validate(claims));
    }

    @Test
    void audienceValidatorIsCalledWhenPresent() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(FAST_RSA_KEY_SIZE);
        KeyPair kp = gen.generateKeyPair();
        PublicKeyInfo keyInfo = new PublicKeyInfo(kp.getPublic(), "kid", ISSUER, List.of("myAud"));

        StandardIssuerValidator issuerValidator = new StandardIssuerValidator(Set.of(ISSUER));
        StandardAudienceValidator audienceValidator = new StandardAudienceValidator();
        StandardTokenClaimsValidator validator = new StandardTokenClaimsValidator(
            Duration.ZERO, issuerValidator, audienceValidator, keyInfo);

        long futureEpoch = (System.currentTimeMillis() + FAR_FUTURE_OFFSET_MS) / MS_PER_SECOND;
        List<TokenClaim> claims = List.of(
            new TokenClaim("iss", ISSUER),
            new TokenClaim("exp", futureEpoch),
            new TokenClaim("aud", "myAud")
        );
        assertDoesNotThrow(() -> validator.validate(claims));
    }
}
