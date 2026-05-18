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

import org.eclipse.ecsp.tokenvalidator.impl.DefaultFallbackKeyStrategy;
import org.eclipse.ecsp.tokenvalidator.impl.DefaultPublicKeyManager;
import org.eclipse.ecsp.tokenvalidator.impl.DefaultTokenValidator;
import org.eclipse.ecsp.tokenvalidator.impl.ExponentialBackoffJwksRetryStrategy;
import org.eclipse.ecsp.tokenvalidator.impl.InMemoryPublicKeyCache;
import org.eclipse.ecsp.tokenvalidator.impl.JwksPublicKeyLoader;
import org.eclipse.ecsp.tokenvalidator.impl.NimbusTokenSignatureValidator;
import org.eclipse.ecsp.tokenvalidator.impl.PemPublicKeyLoader;
import org.eclipse.ecsp.tokenvalidator.impl.StandardIssuerValidator;
import org.eclipse.ecsp.tokenvalidator.impl.StandardTokenParser;
import org.eclipse.ecsp.tokenvalidator.impl.StandardTokenPreprocessor;
import org.eclipse.ecsp.tokenvalidator.impl.WhitelistAlgorithmValidator;
import org.eclipse.ecsp.tokenvalidator.metrics.MicrometerValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.metrics.NoopValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.metrics.TokenValidatorMetricsConfig;
import org.eclipse.ecsp.tokenvalidator.metrics.ValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeyInfo;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Fluent builder for constructing a {@link DefaultTokenValidator} with a fully-configured pipeline.
 *
 * <p>All steps have built-in defaults; override only the steps you need to customise.
 *
 * <p><strong>Simple use case</strong> — provide key sources and trusted issuers; the builder
 * auto-wires the full default key management stack (JWKS + PEM loaders, LRU cache, fallback
 * strategy):
 * <pre>{@code
 * PublicKeySource src = new PublicKeySource();
 * src.setIssuer("https://accounts.example.com");
 * src.setUrl("https://accounts.example.com/.well-known/jwks.json");
 *
 * TokenValidator validator = TokenValidatorBuilder.builder()
 *     .keySources(List.of(src))
 *     .build();
 * }</pre>
 *
 * <p><strong>Advanced use case</strong> — supply a pre-built {@link PublicKeyManager} for full
 * control over loaders, cache, and fallback strategy:
 * <pre>{@code
 * TokenValidator validator = TokenValidatorBuilder.builder()
 *     .publicKeyManager(myCustomManager)
 *     .issuerValidator(myIssuerValidator)
 *     .build();
 * }</pre>
 *
 * @author Abhishek Kumar
 */
public final class TokenValidatorBuilder {

    private PublicKeyManager publicKeyManager;
    private List<PublicKeySource> keySources;
    private Set<String> trustedIssuers;
    private List<String> whitelistedAlgorithms;
    private Duration clockSkew = Duration.ZERO;
    private TokenPreprocessor preprocessor;
    private AlgorithmValidator algorithmValidator;
    private TokenParser tokenParser;
    private TokenSignatureValidator signatureValidator;
    private TokenClaimsValidator claimsValidator;
    private IssuerValidator issuerValidator;
    private AudienceValidator audienceValidator;
    private List<ValidationHook> customValidators;
    private TokenValidatorMetricsConfig metricsConfig;
    private Object meterRegistry;

    private TokenValidatorBuilder() {
    }

    /**
     * Creates a new {@link TokenValidatorBuilder} instance.
     *
     * @return a new builder
     */
    public static TokenValidatorBuilder builder() {
        return new TokenValidatorBuilder();
    }

    /**
     * Required. Provides public key lookup for signature verification.
     *
     * @param manager the public key manager
     * @return this builder
     */
    public TokenValidatorBuilder publicKeyManager(PublicKeyManager manager) {
        this.publicKeyManager = manager;
        return this;
    }

    /**
     * Convenience shortcut: provides one or more {@link PublicKeySource} entries and
     * auto-wires the full default key management stack (JWKS + PEM loaders, LRU cache,
     * {@link DefaultFallbackKeyStrategy}).
     *
     * <p>Use this instead of {@link #publicKeyManager(PublicKeyManager)} for the common
     * case where you only need to point the library at key sources without building the
     * key manager manually. When both {@code keySources} and {@code publicKeyManager} are
     * set, {@code publicKeyManager} takes precedence.
     *
     * <p>If {@link #trustedIssuers(Set)} is not called, the trusted issuer set is derived
     * automatically from the issuers declared in the supplied sources.
     *
     * @param sources the list of key sources (JWKS URL or PEM file path per issuer)
     * @return this builder
     */
    public TokenValidatorBuilder keySources(List<PublicKeySource> sources) {
        this.keySources = sources;
        return this;
    }

    /**
     * Optional. Explicit set of trusted issuer claim values used for token validation.
     *
     * <p>When not set and {@link #keySources(List)} is used, the trusted issuer set is
     * derived automatically from the issuer fields of the supplied sources.
     *
     * <p>Ignored when {@link #issuerValidator(IssuerValidator)} is also set.
     *
     * @param issuers the set of accepted issuer strings
     * @return this builder
     */
    public TokenValidatorBuilder trustedIssuers(Set<String> issuers) {
        this.trustedIssuers = issuers;
        return this;
    }

    /**
     * Convenience: builds a {@link WhitelistAlgorithmValidator} from the given list.
     *
     * <p>Ignored if {@link #algorithmValidator(AlgorithmValidator)} is also set.
     *
     * @param algorithms the list of allowed algorithm names
     * @return this builder
     */
    public TokenValidatorBuilder whitelistedAlgorithms(List<String> algorithms) {
        this.whitelistedAlgorithms = algorithms;
        return this;
    }

    /**
     * Optional. Symmetric clock-skew tolerance for exp/nbf validation. Default: {@link Duration#ZERO}.
     *
     * @param skew the clock skew duration
     * @return this builder
     */
    public TokenValidatorBuilder clockSkew(Duration skew) {
        this.clockSkew = skew != null ? skew : Duration.ZERO;
        return this;
    }

    /**
     * Optional. Replaces the built-in {@link StandardTokenPreprocessor} (step 0).
     *
     * @param preprocessorImpl the custom preprocessor
     * @return this builder
     */
    public TokenValidatorBuilder preprocessor(TokenPreprocessor preprocessorImpl) {
        this.preprocessor = preprocessorImpl;
        return this;
    }

    /**
     * Optional. Replaces {@link WhitelistAlgorithmValidator} (step 2).
     *
     * <p>When set, overrides {@link #whitelistedAlgorithms(List)}.
     *
     * @param validator the custom algorithm validator
     * @return this builder
     */
    public TokenValidatorBuilder algorithmValidator(AlgorithmValidator validator) {
        this.algorithmValidator = validator;
        return this;
    }

    /**
     * Optional. Replaces {@link StandardTokenParser} (step 1).
     *
     * @param parser the custom token parser
     * @return this builder
     */
    public TokenValidatorBuilder tokenParser(TokenParser parser) {
        this.tokenParser = parser;
        return this;
    }

    /**
     * Optional. Replaces {@link NimbusTokenSignatureValidator} (step 4).
     *
     * @param validator the custom signature validator
     * @return this builder
     */
    public TokenValidatorBuilder signatureValidator(TokenSignatureValidator validator) {
        this.signatureValidator = validator;
        return this;
    }

    /**
     * Optional. Replaces the default claims validator (step 5).
     *
     * @param validator the custom claims validator
     * @return this builder
     */
    public TokenValidatorBuilder claimsValidator(TokenClaimsValidator validator) {
        this.claimsValidator = validator;
        return this;
    }

    /**
     * Optional. Replaces the built-in issuer validator inside the claims validator.
     *
     * @param validator the custom issuer validator
     * @return this builder
     */
    public TokenValidatorBuilder issuerValidator(IssuerValidator validator) {
        this.issuerValidator = validator;
        return this;
    }

    /**
     * Optional. Configures audience validation; omit to skip audience checking entirely.
     *
     * @param validator the audience validator
     * @return this builder
     */
    public TokenValidatorBuilder audienceValidator(AudienceValidator validator) {
        this.audienceValidator = validator;
        return this;
    }

    /**
     * Optional. Registers post-pipeline {@link ValidationHook} instances executed in
     * ascending {@link ValidationHook#getOrder()} value.
     *
     * @param hooks the list of hooks
     * @return this builder
     */
    public TokenValidatorBuilder customValidators(List<ValidationHook> hooks) {
        this.customValidators = hooks;
        return this;
    }

    /**
     * Optional. Customises Micrometer metric prefix, per-metric name overrides,
     * per-metric suppression, and global enable/disable.
     *
     * <p>Use this together with {@link #meterRegistry(Object)} to activate Micrometer
     * recording. This pattern works identically in plain Java and in Spring Boot:
     * <pre>{@code
     * // Plain Java
     * TokenValidatorMetricsConfig cfg = TokenValidatorMetricsConfig.builder()
     *     .prefix("my.service")
     *     .disableMetric(TokenValidatorMetricsConfig.KEY_CACHE_SIZE)
     *     .build();
     * TokenValidator validator = TokenValidatorBuilder.builder()
     *     .publicKeyManager(...)
     *     .metricsConfig(cfg)
     *     .meterRegistry(new SimpleMeterRegistry())
     *     .build();
     *
     * // Spring Boot \u2014 inject the Spring-managed MeterRegistry
     * \u0040Bean
     * public TokenValidator tokenValidator(PublicKeyManager pkm, MeterRegistry registry) {
     *     return TokenValidatorBuilder.builder()
     *         .publicKeyManager(pkm)
     *         .metricsConfig(cfg)
     *         .meterRegistry(registry)
     *         .build();
     * }
     * }</pre>
     *
     * <p>When using Spring Boot auto-configuration without customising the
     * {@link TokenValidator} bean, omit this method — the auto-configuration reads
     * {@code token.validator.metrics.*} properties and wires everything automatically.
     *
     * @param config the metrics configuration
     * @return this builder
     */
    public TokenValidatorBuilder metricsConfig(TokenValidatorMetricsConfig config) {
        this.metricsConfig = config;
        return this;
    }

    /**
     * Optional. Provides the {@code io.micrometer.core.instrument.MeterRegistry} used to
     * record metrics.
     *
     * <p>When set, the builder automatically constructs a
     * {@link MicrometerValidationMetricsRecorder} using any
     * {@link #metricsConfig(TokenValidatorMetricsConfig)} supplied (or defaults if omitted).
     * This works identically in plain Java and in Spring Boot (inject the Spring-managed
     * {@code MeterRegistry} bean).
     *
     * <p>When using Spring Boot auto-configuration without customising the
     * {@link TokenValidator} bean, omit this method — the auto-configuration injects the
     * registry automatically.
     *
     * <p>The parameter is typed as {@link Object} so that this library can be loaded even
     * when Micrometer is absent from the classpath; pass a
     * {@code io.micrometer.core.instrument.MeterRegistry} instance at runtime.
     *
     * @param registry the MeterRegistry instance
     * @return this builder
     */
    public TokenValidatorBuilder meterRegistry(Object registry) {
        this.meterRegistry = registry;
        return this;
    }

    /**
     * Builds and returns the configured {@link TokenValidator}.
     *
     * <p>When {@link #publicKeyManager(PublicKeyManager)} has not been called, the builder
     * auto-wires a default key manager from the sources supplied via
     * {@link #keySources(List)}. At least one of these two must be provided.
     *
     * @return the configured TokenValidator
     * @throws IllegalStateException if neither publicKeyManager nor keySources is set,
     *                               or if metrics are enabled without a meterRegistry
     */
    public TokenValidator build() {
        if (publicKeyManager == null) {
            if (keySources == null || keySources.isEmpty()) {
                throw new IllegalStateException(
                    "Either publicKeyManager() or keySources() must be set");
            }
            publicKeyManager = buildDefaultPublicKeyManager();
        }
        if (metricsConfig != null && metricsConfig.isEnabled() && meterRegistry == null) {
            throw new IllegalStateException(
                "meterRegistry() must be provided when metrics are enabled. "
                + "Call meterRegistry(yourMeterRegistry) on the builder, or disable metrics with "
                + "TokenValidatorMetricsConfig.builder().enabled(false).build()");
        }
        TokenPreprocessor resolvedPreprocessor = preprocessor != null
            ? preprocessor : new StandardTokenPreprocessor();
        TokenParser resolvedParser = tokenParser != null
            ? tokenParser : new StandardTokenParser();
        AlgorithmValidator resolvedAlgValidator = resolveAlgorithmValidator();
        TokenSignatureValidator resolvedSigValidator = signatureValidator != null
            ? signatureValidator : new NimbusTokenSignatureValidator();
        IssuerValidator resolvedIssuerValidator = resolveIssuerValidator();
        Function<PublicKeyInfo, TokenClaimsValidator> validatorFactory =
            resolveClaimsValidatorFactory(resolvedIssuerValidator);
        ValidationMetricsRecorder resolvedRecorder = resolveMetricsRecorder();
        DefaultTokenValidator.Pipeline pipeline = new DefaultTokenValidator.Pipeline(
            resolvedPreprocessor,
            resolvedParser,
            resolvedAlgValidator,
            resolvedSigValidator,
            validatorFactory,
            customValidators);
        return new DefaultTokenValidator(pipeline, publicKeyManager, resolvedRecorder);
    }

    private ValidationMetricsRecorder resolveMetricsRecorder() {
        if (meterRegistry != null) {
            TokenValidatorMetricsConfig cfg = metricsConfig != null
                ? metricsConfig
                : TokenValidatorMetricsConfig.builder().build();
            return new MicrometerValidationMetricsRecorder(
                (io.micrometer.core.instrument.MeterRegistry) meterRegistry, cfg);
        }
        return NoopValidationMetricsRecorder.INSTANCE;
    }

    private AlgorithmValidator resolveAlgorithmValidator() {
        if (algorithmValidator != null) {
            return algorithmValidator;
        }
        if (whitelistedAlgorithms != null && !whitelistedAlgorithms.isEmpty()) {
            return new WhitelistAlgorithmValidator(whitelistedAlgorithms);
        }
        return new WhitelistAlgorithmValidator(List.of("RS256", "ES256"));
    }

    private IssuerValidator resolveIssuerValidator() {
        if (issuerValidator != null) {
            return issuerValidator;
        }
        if (trustedIssuers != null) {
            return new StandardIssuerValidator(trustedIssuers);
        }
        if (keySources != null && !keySources.isEmpty()) {
            Set<String> derived = keySources.stream()
                .map(PublicKeySource::getIssuer)
                .filter(iss -> iss != null && !iss.isBlank())
                .collect(Collectors.toSet());
            return new StandardIssuerValidator(derived);
        }
        return new StandardIssuerValidator(Set.of());
    }

    private Function<PublicKeyInfo, TokenClaimsValidator> resolveClaimsValidatorFactory(
        IssuerValidator resolvedIssuerValidator) {
        if (claimsValidator != null) {
            return keyInfo -> claimsValidator;
        }
        return DefaultTokenValidator.defaultClaimsValidatorFactory(
            clockSkew, resolvedIssuerValidator, audienceValidator);
    }

    /**
     * Auto-wires a {@link DefaultPublicKeyManager} using all built-in defaults.
     *
     * <p>The constructed manager uses:
     * <ul>
     *   <li>{@link JwksPublicKeyLoader} for JWKS URL sources</li>
     *   <li>{@link PemPublicKeyLoader} for PEM file sources</li>
     *   <li>{@link InMemoryPublicKeyCache} with default LRU capacity</li>
     *   <li>{@link DefaultFallbackKeyStrategy} for cache-miss fallback</li>
     * </ul>
     *
     * @return a fully configured DefaultPublicKeyManager
     */
    private DefaultPublicKeyManager buildDefaultPublicKeyManager() {
        List<PublicKeySource> sources = List.copyOf(keySources);
        PublicKeySourceProvider provider = () -> sources;
        return new DefaultPublicKeyManager(
            List.of(new JwksPublicKeyLoader(
                new ExponentialBackoffJwksRetryStrategy()), new PemPublicKeyLoader()),
            List.of(provider),
            new InMemoryPublicKeyCache(),
            new DefaultFallbackKeyStrategy(),
            false
        );
    }
}
