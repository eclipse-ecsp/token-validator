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

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.ecsp.tokenvalidator.TokenParser;
import org.eclipse.ecsp.tokenvalidator.exception.MalformedTokenException;
import org.eclipse.ecsp.tokenvalidator.exception.UnsupportedTokenTypeException;
import org.eclipse.ecsp.tokenvalidator.model.ParsedToken;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.text.ParseException;
import java.util.Map;

/**
 * Default implementation of {@link TokenParser} using nimbus-jose-jwt.
 *
 * <p>Detects 5-part compact JWE tokens and immediately throws
 * {@link UnsupportedTokenTypeException}. Parses JWS tokens and populates
 * a {@link ParsedToken} with unverified header and payload data.
 *
 * @author Abhishek Kumar
 */
public class StandardTokenParser implements TokenParser {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(StandardTokenParser.class);

    /** JWE compact tokens have 5 parts separated by dots. */
    private static final int JWE_PART_COUNT = 5;

    /**
     * Constructs a new StandardTokenParser.
     */
    public StandardTokenParser() {
        // No-args constructor for bean registration in the Spring application context
    }

    /**
     * Parses the token and extracts kid, algorithm, issuer and raw claims.
     *
     * @param token the raw JWT string
     * @return ParsedToken containing unverified header and payload data
     * @throws MalformedTokenException       if the token format is invalid
     * @throws UnsupportedTokenTypeException if a JWE (encrypted) token is detected
     */
    @Override
    public ParsedToken parse(String token) throws MalformedTokenException {
        if (token == null || token.isBlank()) {
            throw new MalformedTokenException("Token is null or blank");
        }
        detectJwe(token);
        return parseJws(token);
    }

    private void detectJwe(String token) {
        String[] parts = token.split("\\.");
        if (parts.length == JWE_PART_COUNT) {
            throw new UnsupportedTokenTypeException(
                "JWE (encrypted) tokens are not supported; only signed JWTs are accepted");
        }
    }

    private ParsedToken parseJws(String token) {
        try {
            SignedJWT signedJwt = SignedJWT.parse(token);
            String kid = signedJwt.getHeader().getKeyID();
            String alg = signedJwt.getHeader().getAlgorithm().getName();
            JWTClaimsSet claims = signedJwt.getJWTClaimsSet();
            String iss = claims.getIssuer();
            Map<String, Object> rawClaims = claims.getClaims();
            LOGGER.debug("Token parsed successfully: alg={}", alg);
            return new ParsedToken(kid, alg, iss, rawClaims);
        } catch (ParseException ex) {
            throw new MalformedTokenException("Failed to parse JWT token: " + ex.getMessage(), ex);
        }
    }
}
