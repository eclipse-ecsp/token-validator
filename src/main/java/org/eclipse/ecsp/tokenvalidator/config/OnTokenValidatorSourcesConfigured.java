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

import org.eclipse.ecsp.tokenvalidator.PublicKeySourceProvider;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.springframework.boot.autoconfigure.condition.ConditionMessage;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;
import java.util.Collections;
import java.util.List;
import static org.eclipse.ecsp.tokenvalidator.config.TokenValidatorPropertyNames.SOURCES_PROPERTY;

/**
 * A {@link SpringBootCondition} that matches when the token validator has sufficient
 * configuration to activate its auto-configuration pipeline.
 *
 * <p>The condition matches when <em>either</em> of the following is true:
 * <ol>
 *   <li>At least one {@code token.validator.key-sources} entry is present in the
 *       environment, so the default {@link JwtPropertiesPublicKeySourceProvider}
 *       can be registered.</li>
 *   <li>A custom {@link PublicKeySourceProvider} bean is already registered in the
 *       bean factory, meaning the consumer has supplied their own key-source
 *       implementation (e.g. loaded from a database or remote config) and still
 *       wants the rest of the pipeline ({@code PublicKeyManager},
 *       {@code PublicKeyRefreshScheduler}, {@code TokenValidator}) auto-configured.</li>
 * </ol>
 *
 * <p>When neither condition is met, the entire {@link TokenValidatorAutoConfiguration}
 * is skipped, leaving the application context healthy.
 *
 * <p>User-defined beans are registered in the bean factory before auto-configurations
 * are processed, so the registry check is reliable at class-level condition evaluation
 * time.
 *
 * @author Abhishek Kumar
 */
class OnTokenValidatorSourcesConfigured extends SpringBootCondition {

    private static final String ON_TOKEN_VALIDATOR_SOURCES_CONFIGURED = "OnTokenValidatorSourcesConfigured";

    @Override
    public ConditionOutcome getMatchOutcome(ConditionContext context,
                                            AnnotatedTypeMetadata metadata) {
        // 1 — check whether token.validator.key-sources is populated
        List<PublicKeySource> sources = Binder.get(context.getEnvironment())
            .bind(SOURCES_PROPERTY, Bindable.listOf(PublicKeySource.class))
            .orElse(Collections.emptyList());

        if (!sources.isEmpty()) {
            return ConditionOutcome.match(
                ConditionMessage.forCondition(ON_TOKEN_VALIDATOR_SOURCES_CONFIGURED)
                    .found(SOURCES_PROPERTY)
                    .items(sources.size() + " source(s)"));
        }

        // 2 — check whether the consumer has already registered a custom provider
        String[] customProviders = context.getBeanFactory()
            .getBeanNamesForType(PublicKeySourceProvider.class, true, false);

        if (customProviders.length > 0) {
            return ConditionOutcome.match(
                ConditionMessage.forCondition(ON_TOKEN_VALIDATOR_SOURCES_CONFIGURED)
                    .found("custom PublicKeySourceProvider bean")
                    .items((Object[]) customProviders));
        }

        return ConditionOutcome.noMatch(
            ConditionMessage.forCondition(ON_TOKEN_VALIDATOR_SOURCES_CONFIGURED)
                .didNotFind(SOURCES_PROPERTY + " or a custom PublicKeySourceProvider bean")
                .atAll());
    }
}
