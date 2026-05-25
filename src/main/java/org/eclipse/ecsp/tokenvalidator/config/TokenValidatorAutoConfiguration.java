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

package org.eclipse.ecsp.tokenvalidator.config;

import org.eclipse.ecsp.tokenvalidator.PublicKeyCache;
import org.eclipse.ecsp.tokenvalidator.PublicKeyLoader;
import org.eclipse.ecsp.tokenvalidator.PublicKeyManager;
import org.eclipse.ecsp.tokenvalidator.PublicKeySourceProvider;
import org.eclipse.ecsp.tokenvalidator.TokenValidator;
import org.eclipse.ecsp.tokenvalidator.TokenValidatorBuilder;
import org.eclipse.ecsp.tokenvalidator.impl.DefaultFallbackKeyStrategy;
import org.eclipse.ecsp.tokenvalidator.impl.DefaultPublicKeyManager;
import org.eclipse.ecsp.tokenvalidator.impl.ExponentialBackoffJwksRetryStrategy;
import org.eclipse.ecsp.tokenvalidator.impl.InMemoryPublicKeyCache;
import org.eclipse.ecsp.tokenvalidator.impl.JwksPublicKeyLoader;
import org.eclipse.ecsp.tokenvalidator.impl.JwtPropertiesPublicKeySourceProvider;
import org.eclipse.ecsp.tokenvalidator.impl.PemPublicKeyLoader;
import org.eclipse.ecsp.tokenvalidator.impl.StandardAudienceValidator;
import org.eclipse.ecsp.tokenvalidator.impl.StandardIssuerValidator;
import org.eclipse.ecsp.tokenvalidator.metrics.NoopValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.metrics.TokenValidatorMetricsConfig;
import org.eclipse.ecsp.tokenvalidator.metrics.ValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Spring Boot auto-configuration for the token validator library.
 *
 * <p>Registered in
 * {@code META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}.
 * Constructs and registers all beans from {@link TokenValidatorProperties}.
 * Each bean uses {@code @ConditionalOnMissingBean} so applications can override
 * any bean without disabling auto-configuration.
 *
 * @author Abhishek Kumar
 */
@AutoConfiguration
@Conditional(OnTokenValidatorSourcesConfigured.class)
@EnableConfigurationProperties(TokenValidatorProperties.class)
public class TokenValidatorAutoConfiguration {

    /**
     * Provides the default public key source provider backed by properties.
     *
     * <p>Only registered when at least one {@code token.validator.key-sources} entry is present
     * in the environment. If no sources are configured, this bean — and all beans that depend
     * on {@link PublicKeySourceProvider} — are skipped, leaving the application context healthy.
     *
     * @param properties the bound token validator properties
     * @return a JwtPropertiesPublicKeySourceProvider
     */
    @Bean
    @ConditionalOnMissingBean(PublicKeySourceProvider.class)
    @Conditional(OnTokenValidatorSourcesConfigured.class)
    public JwtPropertiesPublicKeySourceProvider jwtPropertiesPublicKeySourceProvider(
        TokenValidatorProperties properties) {
        return new JwtPropertiesPublicKeySourceProvider(properties.getKeySources());
    }

    /**
     * Provides the default JWKS public key loader. Registered as a bean so Spring
     * manages its lifecycle and closes the underlying HTTP client on context shutdown.
     *
     * @param recorderProvider optional metrics recorder provider
     * @return a JwksPublicKeyLoader
     */
    @Bean
    @ConditionalOnMissingBean(JwksPublicKeyLoader.class)
    public JwksPublicKeyLoader jwksPublicKeyLoader(
        ObjectProvider<ValidationMetricsRecorder> recorderProvider) {
        ValidationMetricsRecorder recorder = recorderProvider.getIfAvailable(
            NoopValidationMetricsRecorder::new);
        return new JwksPublicKeyLoader(new ExponentialBackoffJwksRetryStrategy(), recorder);
    }

    /**
     * Provides the default PEM public key loader.
     *
     * @return a PemPublicKeyLoader
     */
    @Bean
    @ConditionalOnMissingBean(PemPublicKeyLoader.class)
    public PemPublicKeyLoader pemPublicKeyLoader() {
        return new PemPublicKeyLoader();
    }

    /**
     * Provides the default in-memory public key cache and binds the cache-size gauge
     * when a metrics recorder is available.
     *
     * @param properties       the bound token validator properties
     * @param recorderProvider optional metrics recorder provider
     * @return an InMemoryPublicKeyCache
     */
    @Bean
    @ConditionalOnMissingBean(PublicKeyCache.class)
    public InMemoryPublicKeyCache inMemoryPublicKeyCache(
        TokenValidatorProperties properties,
        ObjectProvider<ValidationMetricsRecorder> recorderProvider) {
        InMemoryPublicKeyCache cache =
            new InMemoryPublicKeyCache(properties.getCache().getMaxSize());
        recorderProvider.ifAvailable(recorder -> recorder.bindCacheSizeGauge(cache::size));
        return cache;
    }

    /**
     * Provides the default public key manager.
     *
     * <p>Injects all registered {@link PublicKeyLoader} beans so that custom loaders
     * added by consumers are automatically included. Fails fast at startup if no key
     * sources are configured.
     *
     * @param properties     the bound token validator properties
     * @param sourceProvider the public key source provider
     * @param cache          the public key cache
     * @param loaders        all registered PublicKeyLoader beans
     * @param pemLoader      the PEM public key loader, passed to the fallback strategy
     * @param recorderProvider optional metrics recorder provider
     * @return a DefaultPublicKeyManager
     */
    @Bean
    @ConditionalOnMissingBean(PublicKeyManager.class)
    public DefaultPublicKeyManager defaultPublicKeyManager(
        TokenValidatorProperties properties,
        PublicKeySourceProvider sourceProvider,
        PublicKeyCache cache,
        List<PublicKeyLoader> loaders,
        PemPublicKeyLoader pemLoader,
        ObjectProvider<ValidationMetricsRecorder> recorderProvider) {
        ValidationMetricsRecorder recorder = recorderProvider.getIfAvailable(
            NoopValidationMetricsRecorder::new);
        List<PublicKeySource> sources = sourceProvider.keySources();
        return new DefaultPublicKeyManager(
            loaders,
            List.of(sourceProvider),
            cache,
            new DefaultFallbackKeyStrategy(pemLoader, sources),
            properties.isFailOnStartupError(),
            recorder);
    }

    /**
     * Provides the default metrics configuration when Micrometer is on the classpath.
     *
     * @param properties the bound token validator properties
     * @return a TokenValidatorMetricsConfig
     */
    @Bean
    @ConditionalOnMissingBean(TokenValidatorMetricsConfig.class)
    @ConditionalOnClass(name = "io.micrometer.core.instrument.MeterRegistry")
    public TokenValidatorMetricsConfig tokenValidatorMetricsConfig(
        TokenValidatorProperties properties) {
        TokenValidatorProperties.MetricsProperties mp = properties.getMetrics();
        TokenValidatorMetricsConfig.Builder builder = TokenValidatorMetricsConfig.builder()
            .enabled(mp.isEnabled())
            .prefix(mp.getPrefix());
        mp.getNames().forEach(builder::metricName);
        mp.getDisabledMetrics().forEach(builder::disableMetric);
        return builder.build();
    }

    /**
     * Provides the default PublicKeyRefreshScheduler.
     *
     * @param publicKeyManager the public key manager
     * @param sourceProvider   the public key source provider
     * @return a PublicKeyRefreshScheduler
     */
    @Bean
    @ConditionalOnMissingBean(PublicKeyRefreshScheduler.class)
    public PublicKeyRefreshScheduler publicKeyRefreshScheduler(
        PublicKeyManager publicKeyManager,
        PublicKeySourceProvider sourceProvider) {
        return new PublicKeyRefreshScheduler(publicKeyManager, sourceProvider);
    }

    /**
     * Provides the default TokenValidator when Micrometer is <em>not</em> on the classpath.
     *
     * <p>No {@code MeterRegistry} is available in this case, so metric recording falls back
     * to the Noop implementation automatically inside the builder.
     *
     * @param properties       the bound token validator properties
     * @param publicKeyManager the public key manager
     * @param sourceProvider   the public key source provider
     * @param metricsConfigProvider optional metrics config provider
     * @return the configured TokenValidator
     */
    @Bean
    @ConditionalOnMissingBean(TokenValidator.class)
    @ConditionalOnMissingClass("io.micrometer.core.instrument.MeterRegistry")
    public TokenValidator defaultTokenValidator(
        TokenValidatorProperties properties,
        PublicKeyManager publicKeyManager,
        PublicKeySourceProvider sourceProvider,
        ObjectProvider<TokenValidatorMetricsConfig> metricsConfigProvider) {
        return buildTokenValidator(properties, publicKeyManager, sourceProvider,
            metricsConfigProvider.getIfAvailable(() -> TokenValidatorMetricsConfig.builder().build()),
            null);
    }

    private static TokenValidator buildTokenValidator(
        TokenValidatorProperties properties,
        PublicKeyManager publicKeyManager,
        PublicKeySourceProvider sourceProvider,
        TokenValidatorMetricsConfig metricsConfig,
        Object meterRegistry) {
        Set<String> issuers = sourceProvider.keySources().stream()
            .map(PublicKeySource::getIssuer)
            .collect(Collectors.toSet());
        boolean hasAudience = sourceProvider.keySources().stream()
            .anyMatch(src -> src.getAudiences() != null && !src.getAudiences().isEmpty());
        TokenValidatorBuilder tvBuilder = TokenValidatorBuilder.builder()
            .publicKeyManager(publicKeyManager)
            .whitelistedAlgorithms(properties.getWhitelistedAlgorithms())
            .clockSkew(properties.getClockSkew())
            .issuerValidator(new StandardIssuerValidator(issuers));
        if (meterRegistry != null) {
            tvBuilder.metricsConfig(metricsConfig).meterRegistry(meterRegistry);
        }
        if (hasAudience) {
            tvBuilder.audienceValidator(new StandardAudienceValidator());
        }
        return tvBuilder.build();
    }

    /**
     * Inner configuration for Micrometer-specific beans.
     *
     * <p>This class is only processed when {@code io.micrometer.core.instrument.MeterRegistry}
     * is on the classpath, ensuring that classes referencing Micrometer types are never
     * loaded in environments where Micrometer is absent.
     *
     * <p>The {@link Conditional @Conditional} mirrors the outer class so that this
     * configuration is not activated if the enclosing
     * {@link TokenValidatorAutoConfiguration} is excluded or if no key sources are
     * configured.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "io.micrometer.core.instrument.MeterRegistry")
    @Conditional(OnTokenValidatorSourcesConfigured.class)
    static class MicrometerConfiguration {

        /**
         * Provides the default TokenValidator when Micrometer is on the classpath.
         *
         * <p>Injects the Spring-managed {@link io.micrometer.core.instrument.MeterRegistry}
         * and passes it to the builder so the builder can internally construct a
         * {@link org.eclipse.ecsp.tokenvalidator.metrics.MicrometerValidationMetricsRecorder}.
         * The recorder type is never exposed through the builder's public API.
         *
         * @param meterRegistry        the Micrometer MeterRegistry
         * @param properties           the bound token validator properties
         * @param publicKeyManager     the public key manager
         * @param sourceProvider       the public key source provider
         * @param configProvider       optional provider for the metrics config
         * @return the configured TokenValidator
         */
        @Bean
        @ConditionalOnMissingBean(TokenValidator.class)
        public TokenValidator defaultTokenValidator(
            io.micrometer.core.instrument.MeterRegistry meterRegistry,
            TokenValidatorProperties properties,
            PublicKeyManager publicKeyManager,
            PublicKeySourceProvider sourceProvider,
            ObjectProvider<TokenValidatorMetricsConfig> configProvider) {
            TokenValidatorMetricsConfig cfg = configProvider.getIfAvailable(
                () -> TokenValidatorMetricsConfig.builder().build());
            return buildTokenValidator(properties, publicKeyManager, sourceProvider, cfg, meterRegistry);
        }

        /**
         * Registers the Micrometer-backed metrics recorder when Micrometer is available.
         *
         * @param meterRegistry    the Micrometer MeterRegistry
         * @param configProvider   optional provider for the metrics config
         * @return the Micrometer-backed ValidationMetricsRecorder
         */
        @Bean
        @ConditionalOnMissingBean(ValidationMetricsRecorder.class)
        public ValidationMetricsRecorder micrometerValidationMetricsRecorder(
            io.micrometer.core.instrument.MeterRegistry meterRegistry,
            ObjectProvider<TokenValidatorMetricsConfig> configProvider) {
            TokenValidatorMetricsConfig config = configProvider.getIfAvailable(
                () -> TokenValidatorMetricsConfig.builder().build());
            return new org.eclipse.ecsp.tokenvalidator.metrics
                .MicrometerValidationMetricsRecorder(meterRegistry, config);
        }
    }
}
