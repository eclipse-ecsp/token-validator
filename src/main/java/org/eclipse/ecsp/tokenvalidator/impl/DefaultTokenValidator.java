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

import org.eclipse.ecsp.tokenvalidator.AlgorithmValidator;
import org.eclipse.ecsp.tokenvalidator.AudienceValidator;
import org.eclipse.ecsp.tokenvalidator.IssuerValidator;
import org.eclipse.ecsp.tokenvalidator.PublicKeyManager;
import org.eclipse.ecsp.tokenvalidator.TokenClaimsValidator;
import org.eclipse.ecsp.tokenvalidator.TokenParser;
import org.eclipse.ecsp.tokenvalidator.TokenPreprocessor;
import org.eclipse.ecsp.tokenvalidator.TokenSignatureValidator;
import org.eclipse.ecsp.tokenvalidator.TokenValidator;
import org.eclipse.ecsp.tokenvalidator.ValidationHook;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidClaimException;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidSignatureException;
import org.eclipse.ecsp.tokenvalidator.exception.InvalidTokenException;
import org.eclipse.ecsp.tokenvalidator.exception.KeyNotFoundException;
import org.eclipse.ecsp.tokenvalidator.exception.TokenExpiredException;
import org.eclipse.ecsp.tokenvalidator.metrics.NoopValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.metrics.ValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.model.ParsedToken;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.TokenClaim;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

/**
 * Concrete implementation of {@link TokenValidator} executing the 7-step pipeline.
 *
 * <p>No step is hard-coded — any collaborator can be replaced via
 * {@link org.eclipse.ecsp.tokenvalidator.TokenValidatorBuilder} without subclassing.
 * Measures latency and result via Micrometer when configured.
 *
 * @author Abhishek Kumar
 */
public class DefaultTokenValidator implements TokenValidator {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(DefaultTokenValidator.class);

    private final TokenPreprocessor preprocessor;
    private final TokenParser tokenParser;
    private final AlgorithmValidator algorithmValidator;
    private final PublicKeyManager publicKeyManager;
    private final TokenSignatureValidator signatureValidator;
    private final Function<PublicKeyInfo, TokenClaimsValidator> claimsValidatorFactory;
    private final List<ValidationHook> hooks;
    private final ValidationMetricsRecorder metricsRecorder;

    /**
     * Groups the stateless validation pipeline step collaborators for
     * {@link DefaultTokenValidator}.
     *
     * <p>Passed to the {@link DefaultTokenValidator} constructor so that all six
     * pipeline steps can be supplied as a single argument, keeping the constructor
     * parameter count within the authorised limit.
     *
     * @param preprocessor           the token preprocessor (step 0)
     * @param tokenParser            the token parser (step 1)
     * @param algorithmValidator     the algorithm validator (step 2)
     * @param signatureValidator     the signature validator (step 4)
     * @param claimsValidatorFactory factory producing a claims validator for a resolved key (step 5)
     * @param hooks                  the list of validation hooks (step 6)
     */
    public record Pipeline(
        TokenPreprocessor preprocessor,
        TokenParser tokenParser,
        AlgorithmValidator algorithmValidator,
        TokenSignatureValidator signatureValidator,
        Function<PublicKeyInfo, TokenClaimsValidator> claimsValidatorFactory,
        List<ValidationHook> hooks) {}

    /**
     * Constructs a DefaultTokenValidator using all pipeline steps and
     * {@link NoopValidationMetricsRecorder} for observability.
     *
     * @param pipeline         the grouped pipeline step collaborators
     * @param publicKeyManager the public key manager (step 3)
     */
    public DefaultTokenValidator(Pipeline pipeline, PublicKeyManager publicKeyManager) {
        this(pipeline, publicKeyManager, NoopValidationMetricsRecorder.INSTANCE);
    }

    /**
     * Constructs a DefaultTokenValidator using all pipeline steps and a metrics recorder.
     *
     * @param pipeline         the grouped pipeline step collaborators
     * @param publicKeyManager the public key manager (step 3)
     * @param metricsRecorder  the metrics recorder for observability
     */
    public DefaultTokenValidator(
        Pipeline pipeline,
        PublicKeyManager publicKeyManager,
        ValidationMetricsRecorder metricsRecorder) {
        this.preprocessor = pipeline.preprocessor();
        this.tokenParser = pipeline.tokenParser();
        this.algorithmValidator = pipeline.algorithmValidator();
        this.publicKeyManager = publicKeyManager;
        this.signatureValidator = pipeline.signatureValidator();
        this.claimsValidatorFactory = pipeline.claimsValidatorFactory();
        this.hooks = pipeline.hooks() == null ? List.of() : sortHooks(pipeline.hooks());
        this.metricsRecorder = metricsRecorder != null
            ? metricsRecorder : NoopValidationMetricsRecorder.INSTANCE;
    }

    /**
     * Validates the given JWT token through the full 7-step pipeline.
     *
     * @param token the JWT token to validate (may be Bearer-prefixed)
     * @return the verified claims from the token
     * @throws InvalidTokenException     if the token is malformed or invalid
     * @throws TokenExpiredException     if the token is expired
     * @throws InvalidSignatureException if signature verification fails
     * @throws KeyNotFoundException      if the public key for validation is not found
     * @throws InvalidClaimException     if claim validation fails
     */
    @Override
    public List<TokenClaim> validate(String token)
        throws InvalidTokenException, TokenExpiredException,
            InvalidSignatureException, KeyNotFoundException, InvalidClaimException {
        long startNanos = System.nanoTime();
        String issuer = null;
        boolean success = false;
        try {
            // Step 0: preprocess
            String preprocessed = preprocessor.preprocess(token);
            // Step 1: parse
            ParsedToken parsedToken = tokenParser.parse(preprocessed);
            issuer = parsedToken.getIss();
            // Step 2: algorithm validation
            algorithmValidator.validate(parsedToken);
            // Step 3: key lookup
            Optional<PublicKeyInfo> keyInfo = publicKeyManager.findPublicKey(
                parsedToken.getKid(), parsedToken.getIss());
            if (keyInfo.isEmpty()) {
                LOGGER.error("No public key found for issuer={} kid={}",
                    parsedToken.getIss(), parsedToken.getKid());
                throw new KeyNotFoundException(
                    "No public key found for issuer='" + parsedToken.getIss()
                        + "' kid='" + parsedToken.getKid() + "'");
            }
            // Step 4: signature verification
            List<TokenClaim> claims;
            try {
                claims = signatureValidator.validate(preprocessed, keyInfo.get().getPublicKey());
            } catch (InvalidSignatureException ex) {
                metricsRecorder.recordSignatureFailure(
                    issuer != null ? issuer : "unknown");
                throw ex;
            }
            // Step 5: claims validation
            TokenClaimsValidator claimsValidator = claimsValidatorFactory.apply(keyInfo.get());
            claimsValidator.validate(claims);
            // Step 6: hooks
            runHooks(claims);
            LOGGER.debug("Token validated successfully for issuer={}", parsedToken.getIss());
            success = true;
            return claims;
        } finally {
            long durationNanos = System.nanoTime() - startNanos;
            metricsRecorder.recordValidation(
                issuer != null ? issuer : "unknown", success, durationNanos);
        }
    }

    private void runHooks(List<TokenClaim> claims) {
        for (ValidationHook hook : hooks) {
            hook.validate(claims);
        }
    }

    private List<ValidationHook> sortHooks(List<ValidationHook> hookList) {
        return hookList.stream()
            .sorted(Comparator.comparingInt(ValidationHook::getOrder))
            .toList();
    }

    /**
     * Creates a builder for this validator — delegates to
     * {@link org.eclipse.ecsp.tokenvalidator.TokenValidatorBuilder}.
     *
     * @param clockSkew         clock skew tolerance
     * @param issuerValidator   issuer validator
     * @param audienceValidator audience validator (may be null)
     * @return a factory Function mapping PublicKeyInfo to TokenClaimsValidator
     */
    public static Function<PublicKeyInfo, TokenClaimsValidator> defaultClaimsValidatorFactory(
        Duration clockSkew,
        IssuerValidator issuerValidator,
        AudienceValidator audienceValidator) {
        return keyInfo -> StandardTokenClaimsValidator.of(
            clockSkew, issuerValidator, audienceValidator, Optional.of(keyInfo));
    }
}
