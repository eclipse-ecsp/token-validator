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

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.eclipse.ecsp.tokenvalidator.TokenSignatureValidator;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidSignatureException;
import org.eclipse.ecsp.tokenvalidator.exception.MalformedTokenException;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Signature validator using nimbus-jose-jwt for RSA and EC key verification.
 *
 * <p>Does NOT enforce expiration during signature verification; {@code exp} enforcement
 * is performed exclusively by {@code TokenClaimsValidator}.
 *
 * @author Abhishek Kumar
 */
public class NimbusTokenSignatureValidator implements TokenSignatureValidator {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(NimbusTokenSignatureValidator.class);

    /**
     * Constructs a new NimbusTokenSignatureValidator.
     */
    public NimbusTokenSignatureValidator() {
        // No-args constructor for bean registration in the Spring application context
    }

    /**
     * Verifies the JWT signature using nimbus-jose-jwt and returns the verified claims.
     *
     * @param token     the raw JWT string
     * @param publicKey the public key to verify against (RSA or EC)
     * @return list of verified claims extracted from the token
     * @throws InvalidSignatureException if the signature is invalid or verification fails
     * @throws MalformedTokenException   if the token cannot be parsed
     */
    @Override
    public List<TokenClaim> validate(String token, PublicKey publicKey)
        throws InvalidSignatureException, MalformedTokenException {
        try {
            SignedJWT signedJwt = SignedJWT.parse(token);
            JWSVerifier verifier = buildVerifier(publicKey);
            boolean verified = signedJwt.verify(verifier);
            if (!verified) {
                LOGGER.error("JWT signature verification failed");
                throw new InvalidSignatureException("JWT signature verification failed");
            }
            JWTClaimsSet claimsSet = signedJwt.getJWTClaimsSet();
            return buildTokenClaims(claimsSet.getClaims());
        } catch (ParseException ex) {
            throw new MalformedTokenException("Failed to parse token for signature verification", ex);
        } catch (com.nimbusds.jose.JOSEException ex) {
            throw new InvalidSignatureException("Signature verification error: " + ex.getMessage(), ex);
        }
    }

    private JWSVerifier buildVerifier(PublicKey publicKey) throws com.nimbusds.jose.JOSEException {
        if (publicKey instanceof RSAPublicKey rsaKey) {
            return new RSASSAVerifier(rsaKey);
        } else if (publicKey instanceof ECPublicKey ecKey) {
            return new ECDSAVerifier(ecKey);
        }
        throw new InvalidSignatureException(
            "Unsupported key type: " + publicKey.getClass().getName());
    }

    private List<TokenClaim> buildTokenClaims(Map<String, Object> claims) {
        List<TokenClaim> result = new ArrayList<>(claims.size());
        for (Map.Entry<String, Object> entry : claims.entrySet()) {
            result.add(new TokenClaim(entry.getKey(), entry.getValue()));
        }
        return result;
    }
}
