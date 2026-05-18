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

import org.eclipse.ecsp.tokenvalidator.PublicKeyManager;
import org.eclipse.ecsp.tokenvalidator.PublicKeySourceProvider;
import org.eclipse.ecsp.tokenvalidator.model.PublicKeySource;
import org.eclipse.ecsp.utils.logger.IgniteLogger;
import org.eclipse.ecsp.utils.logger.IgniteLoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Schedules periodic JWKS refresh and triggers initial parallel key load on startup.
 *
 * <p>Implements {@link ApplicationListener} to perform the initial parallel JWKS fetch
 * for all configured issuers when the application is ready. Implements {@link DisposableBean}
 * to shut down the refresh executor when the context closes.
 *
 * @author Abhishek Kumar
 */
public class PublicKeyRefreshScheduler
    implements ApplicationListener<ApplicationReadyEvent>, DisposableBean {

    private static final IgniteLogger LOGGER =
        IgniteLoggerFactory.getLogger(PublicKeyRefreshScheduler.class);

    /** Maximum seconds to wait for the scheduler to terminate gracefully on shutdown. */
    private static final long SHUTDOWN_TIMEOUT_SECONDS = 10L;

    private final PublicKeyManager publicKeyManager;
    private final PublicKeySourceProvider sourceProvider;
    private final ScheduledExecutorService scheduler;

    /**
     * Constructs a PublicKeyRefreshScheduler with the given manager and source provider.
     *
     * @param publicKeyManager the public key manager to trigger refreshes on
     * @param sourceProvider   the source provider supplying issuer configurations
     */
    public PublicKeyRefreshScheduler(
        PublicKeyManager publicKeyManager,
        PublicKeySourceProvider sourceProvider) {
        this.publicKeyManager = publicKeyManager;
        this.sourceProvider = sourceProvider;
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "key-refresh-scheduler");
            t.setDaemon(true);
            return t;
        });
    }

    /**
     * Handles {@link ApplicationReadyEvent}: triggers parallel initial JWKS load and schedules
     * per-issuer periodic refresh.
     *
     * @param event the application ready event
     */
    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        LOGGER.info("ApplicationReadyEvent received: triggering initial JWKS fetch");
        List<PublicKeySource> sources = sourceProvider.keySources();
        List<Thread> fetchThreads = sources.stream()
            .map(src -> Thread.ofVirtual().start(() -> loadSourceQuietly(src)))
            .toList();
        waitForAll(fetchThreads);
        scheduleRefreshes(sources);
        LOGGER.info("Initial public key load completed for {} sources", sources.size());
    }

    /**
     * Shuts down the refresh executor when the Spring context closes.
     *
     * @throws Exception if shutdown encounters an error
     */
    @Override
    public void destroy() throws Exception {
        LOGGER.info("Shutting down public key refresh scheduler");
        scheduler.shutdown();
        boolean terminated = scheduler.awaitTermination(SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        if (!terminated) {
            scheduler.shutdownNow();
            LOGGER.warn("Refresh scheduler did not terminate gracefully; forced shutdown");
        }
    }

    private void loadSourceQuietly(PublicKeySource source) {
        try {
            publicKeyManager.refreshPublicKeys(source.getIssuer());
        } catch (Exception ex) {
            LOGGER.error("Startup key load failed for issuer={}: {}",
                source.getIssuer(), ex.getMessage());
        }
    }

    private void waitForAll(List<Thread> threads) {
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException _) {
                threads.forEach(Thread::interrupt);
                Thread.currentThread().interrupt();
                LOGGER.warn("Interrupted during initial key load; remaining fetches cancelled");
                return;
            }
        }
    }

    private void scheduleRefreshes(List<PublicKeySource> sources) {
        for (PublicKeySource source : sources) {
            Duration interval = source.getRefreshInterval();
            if (interval != null && !interval.isZero()) {
                long intervalMs = interval.toMillis();
                String issuer = source.getIssuer();
                scheduler.scheduleAtFixedRate(
                    () -> refreshIssuerQuietly(issuer),
                    intervalMs,
                    intervalMs,
                    TimeUnit.MILLISECONDS);
                LOGGER.info("Scheduled refresh for issuer={} every {}ms", issuer, intervalMs);
            }
        }
    }

    private void refreshIssuerQuietly(String issuer) {
        try {
            LOGGER.info("Scheduled refresh triggered for issuer={}", issuer);
            publicKeyManager.refreshPublicKeys(issuer);
        } catch (Exception ex) {
            LOGGER.error("Scheduled refresh failed for issuer={}: {}", issuer, ex.getMessage());
        }
    }
}
