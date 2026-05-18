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
import org.eclipse.ecsp.tokenvalidator.TokenClaimsValidator;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidIssuerException;
import org.eclipse.ecsp.tokenvalidator.exception.TokenExpiredException;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Default claims validator that checks {@code exp}, {@code nbf}, {@code iss},
 * and optionally {@code aud}.
 *
 * <p>The {@code clockSkew} tolerance is applied symmetrically: {@code exp} is accepted
 * if within {@code clockSkew} after the current time, and {@code nbf} is accepted if
 * within {@code clockSkew} before the current time.
 *
 * @author Abhishek Kumar
 */
public class StandardTokenClaimsValidator implements TokenClaimsValidator {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(StandardTokenClaimsValidator.class);

    private final Duration clockSkew;
    private final IssuerValidator issuerValidator;
    private final AudienceValidator audienceValidator;
    private final PublicKeyInfo resolvedKeyInfo;

    /**
     * Constructs a StandardTokenClaimsValidator with all dependencies.
     *
     * @param clockSkew         the clock-skew tolerance for exp/nbf checks (may be zero)
     * @param issuerValidator   the issuer validator (required)
     * @param audienceValidator the audience validator (optional, may be null)
     * @param resolvedKeyInfo   the resolved key info for audience checking (may be null)
     */
    public StandardTokenClaimsValidator(
        Duration clockSkew,
        IssuerValidator issuerValidator,
        AudienceValidator audienceValidator,
        PublicKeyInfo resolvedKeyInfo) {
        this.clockSkew = clockSkew != null ? clockSkew : Duration.ZERO;
        this.issuerValidator = issuerValidator;
        this.audienceValidator = audienceValidator;
        this.resolvedKeyInfo = resolvedKeyInfo;
    }

    /**
     * Validates standard claims: exp, nbf, iss, and optionally aud.
     *
     * @param claims verified claims from the token
     * @throws TokenExpiredException  if the exp claim is in the past beyond clockSkew tolerance
     * @throws InvalidClaimException  if nbf or aud validation fails
     * @throws InvalidIssuerException if the iss claim is absent or not recognised
     */
    @Override
    public void validate(List<TokenClaim> claims)
        throws TokenExpiredException, InvalidClaimException, InvalidIssuerException {
        Map<String, Object> claimMap = claims.stream()
            .collect(Collectors.toMap(TokenClaim::getName, TokenClaim::getValue,
                (existing, replacement) -> existing));
        validateExp(claimMap);
        validateNbf(claimMap);
        String iss = getClaimAsString(claimMap, "iss");
        issuerValidator.validate(iss);
        if (audienceValidator != null) {
            audienceValidator.validate(claimMap.get("aud"), resolvedKeyInfo);
        }
        LOGGER.debug("Claims validated successfully");
    }

    private void validateExp(Map<String, Object> claims) {
        Object expValue = claims.get("exp");
        if (expValue == null) {
            throw new TokenExpiredException("Token is missing the 'exp' claim");
        }
        Instant expInstant = toInstant(expValue);
        Instant now = Instant.now();
        if (now.isAfter(expInstant.plus(clockSkew))) {
            throw new TokenExpiredException("Token has expired (exp=" + expInstant + ")");
        }
    }

    private void validateNbf(Map<String, Object> claims) {
        Object nbfValue = claims.get("nbf");
        if (nbfValue == null) {
            return;
        }
        Instant nbfInstant = toInstant(nbfValue);
        Instant now = Instant.now();
        if (now.isBefore(nbfInstant.minus(clockSkew))) {
            throw new InvalidClaimException(
                "Token is not yet valid (nbf=" + nbfInstant + ")");
        }
    }

    private Instant toInstant(Object value) {
        if (value instanceof Date date) {
            return date.toInstant();
        } else if (value instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }
        throw new InvalidClaimException("Cannot parse time claim value: " + value);
    }

    private String getClaimAsString(Map<String, Object> claims, String claimName) {
        Object val = claims.get(claimName);
        return val != null ? val.toString() : null;
    }

    /**
     * Creates a builder-style factory method that returns a Function to produce validators.
     *
     * @param clockSkew         the clock skew duration
     * @param issuerValidator   the issuer validator
     * @param audienceValidator optional audience validator
     * @return a Function mapping PublicKeyInfo to a new StandardTokenClaimsValidator instance
     */
    public static Function<PublicKeyInfo, StandardTokenClaimsValidator> factory(
        Duration clockSkew,
        IssuerValidator issuerValidator,
        AudienceValidator audienceValidator) {
        return keyInfo -> of(clockSkew, issuerValidator, audienceValidator,
            Optional.ofNullable(keyInfo));
    }

    /**
     * Creates a StandardTokenClaimsValidator with an optional PublicKeyInfo.
     *
     * @param clockSkew         the clock skew duration
     * @param issuerValidator   the issuer validator
     * @param audienceValidator optional audience validator
     * @param keyInfo           optional resolved key info
     * @return a new StandardTokenClaimsValidator
     */
    public static StandardTokenClaimsValidator of(
        Duration clockSkew,
        IssuerValidator issuerValidator,
        AudienceValidator audienceValidator,
        Optional<PublicKeyInfo> keyInfo) {
        return new StandardTokenClaimsValidator(
            clockSkew, issuerValidator, audienceValidator, keyInfo.orElse(null));
    }
}
