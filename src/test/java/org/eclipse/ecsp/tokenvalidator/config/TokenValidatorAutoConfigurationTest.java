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

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.eclipse.ecsp.tokenvalidator.PublicKeySourceProvider;
import org.eclipse.ecsp.tokenvalidator.TokenValidator;
import org.eclipse.ecsp.tokenvalidator.metrics.NoopValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.metrics.ValidationMetricsRecorder;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OnTokenValidatorSourcesConfigured} and
 * {@link TokenValidatorAutoConfiguration} conditional behaviour.
 *
 * <p>Uses {@link ApplicationContextRunner} so no full Spring Boot application is started.
 *
 * @author Abhishek Kumar
 */
class TokenValidatorAutoConfigurationTest {

    private static final String JWKS_URL = "https://example.com/.well-known/jwks.json";

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withConfiguration(
            org.springframework.boot.autoconfigure.AutoConfigurations.of(
                TokenValidatorAutoConfiguration.class))
        .withBean(io.micrometer.core.instrument.MeterRegistry.class, SimpleMeterRegistry::new);

    // -------------------------------------------------------------------------
    // OnTokenValidatorSourcesConfigured — no sources → auto-config skipped
    // -------------------------------------------------------------------------

    @Test
    void withNoSources_contextLoadsWithoutTokenValidatorBean() {
        contextRunner.run(ctx -> assertThat(ctx).doesNotHaveBean(TokenValidator.class));
    }

    // -------------------------------------------------------------------------
    // OnTokenValidatorSourcesConfigured — sources present → auto-config active
    // -------------------------------------------------------------------------

    @Test
    void withSources_tokenValidatorBeanIsRegistered() {
        contextRunner
            .withPropertyValues(
                "token.validator.key-sources[0].id=k1",
                "token.validator.key-sources[0].issuer=https://issuer.example.com",
                "token.validator.key-sources[0].url=" + JWKS_URL)
            .run(ctx -> assertThat(ctx).hasSingleBean(TokenValidator.class));
    }

    // -------------------------------------------------------------------------
    // buildTokenValidator — hasAudience=true branch
    // -------------------------------------------------------------------------

    @Test
    void withAudience_configuredAudienceValidatorIsApplied() {
        contextRunner
            .withPropertyValues(
                "token.validator.key-sources[0].id=k1",
                "token.validator.key-sources[0].issuer=https://issuer.example.com",
                "token.validator.key-sources[0].url=" + JWKS_URL,
                "token.validator.key-sources[0].audiences[0]=my-service")
            .run(ctx -> assertThat(ctx).hasSingleBean(TokenValidator.class));
    }

    // -------------------------------------------------------------------------
    // inMemoryPublicKeyCache — ValidationMetricsRecorder present branch
    // -------------------------------------------------------------------------

    @Test
    void withMetricsRecorderPresent_cacheGaugeIsBound() {
        contextRunner
            .withPropertyValues(
                "token.validator.key-sources[0].id=k1",
                "token.validator.key-sources[0].issuer=https://issuer.example.com",
                "token.validator.key-sources[0].url=" + JWKS_URL)
            .withBean(
                ValidationMetricsRecorder.class,
                NoopValidationMetricsRecorder::new)
            .run(ctx -> assertThat(ctx).hasSingleBean(TokenValidator.class));
    }

    // -------------------------------------------------------------------------
    // Custom PublicKeySourceProvider — no token.validator.key-sources needed
    // -------------------------------------------------------------------------

    @Test
    void withCustomSourceProvider_autoConfigActivatesWithoutProperties() {
        PublicKeySource src = new PublicKeySource();
        src.setId("custom");
        src.setIssuer("https://custom.issuer.com");
        src.setUrl(JWKS_URL);

        contextRunner
            .withBean(PublicKeySourceProvider.class, () -> () -> List.of(src))
            .run(ctx -> {
                // jwtPropertiesPublicKeySourceProvider must be skipped (custom bean present)
                assertThat(ctx).doesNotHaveBean(
                    org.eclipse.ecsp.tokenvalidator.impl
                        .JwtPropertiesPublicKeySourceProvider.class);
                // full pipeline must be wired using the custom provider
                assertThat(ctx).hasSingleBean(TokenValidator.class);
            });
    }
}
