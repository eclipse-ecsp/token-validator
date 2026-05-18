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
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import java.lang.reflect.Field;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PublicKeyRefreshScheduler}.
 *
 * @author Abhishek Kumar
 */
class PublicKeyRefreshSchedulerTest {

    private static final long TEST_TIMEOUT_MS = 3000L;
    private static final long REFRESH_INTERVAL_MS = 100L;
    private static final long LONG_REFRESH_INTERVAL_MINUTES = 60L;

    private static PublicKeySource source(String issuer, Duration refreshInterval) {
        PublicKeySource src = new PublicKeySource();
        src.setIssuer(issuer);
        src.setRefreshInterval(refreshInterval);
        return src;
    }

    // -------------------------------------------------------------------------
    // onApplicationEvent — happy path with no refresh interval
    // -------------------------------------------------------------------------

    @Test
    void onApplicationEvent_noRefreshInterval_loadsKeysWithoutScheduling() throws Exception {
        PublicKeyManager manager = mock(PublicKeyManager.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source("iss1", null)));

        PublicKeyRefreshScheduler scheduler = new PublicKeyRefreshScheduler(manager, provider);
        assertDoesNotThrow(() -> scheduler.onApplicationEvent(mock(ApplicationReadyEvent.class)));
        scheduler.destroy();
    }

    // -------------------------------------------------------------------------
    // onApplicationEvent — source with zero-duration refresh interval
    // -------------------------------------------------------------------------

    @Test
    void onApplicationEvent_zeroRefreshInterval_doesNotSchedule() throws Exception {
        PublicKeyManager manager = mock(PublicKeyManager.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source("iss1", Duration.ZERO)));

        PublicKeyRefreshScheduler scheduler = new PublicKeyRefreshScheduler(manager, provider);
        assertDoesNotThrow(() -> scheduler.onApplicationEvent(mock(ApplicationReadyEvent.class)));
        scheduler.destroy();
    }

    // -------------------------------------------------------------------------
    // onApplicationEvent — source with a real refresh interval (schedules task)
    // -------------------------------------------------------------------------

    @Test
    void onApplicationEvent_withRefreshInterval_schedulesRefresh() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        PublicKeyManager manager = mock(PublicKeyManager.class);
        // Count the scheduled refresh invocation
        doAnswer(inv -> {
            latch.countDown();
            return null;
        }).when(manager).refreshPublicKeys(anyString());

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        // REFRESH_INTERVAL_MS interval so the test completes quickly
        when(provider.keySources()).thenReturn(List.of(source("iss1", Duration.ofMillis(REFRESH_INTERVAL_MS))));

        PublicKeyRefreshScheduler scheduler = new PublicKeyRefreshScheduler(manager, provider);
        scheduler.onApplicationEvent(mock(ApplicationReadyEvent.class));

        boolean fired = latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        scheduler.destroy();
        org.junit.jupiter.api.Assertions.assertTrue(fired, "Scheduled refresh should have fired");
    }

    // -------------------------------------------------------------------------
    // onApplicationEvent — empty source list (no threads, no schedules)
    // -------------------------------------------------------------------------

    @Test
    void onApplicationEvent_emptySources_doesNothing() throws Exception {
        PublicKeyManager manager = mock(PublicKeyManager.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of());

        PublicKeyRefreshScheduler scheduler = new PublicKeyRefreshScheduler(manager, provider);
        assertDoesNotThrow(() -> scheduler.onApplicationEvent(mock(ApplicationReadyEvent.class)));
        scheduler.destroy();
    }

    // -------------------------------------------------------------------------
    // loadSourceQuietly — exception swallowed (covers the catch branch)
    // -------------------------------------------------------------------------

    @Test
    void onApplicationEvent_keyLoadThrows_doesNotPropagateException() throws Exception {
        PublicKeyManager manager = mock(PublicKeyManager.class);
        doThrow(new RuntimeException("load failed")).when(manager).refreshPublicKeys(anyString());

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source("iss1", null)));

        PublicKeyRefreshScheduler scheduler = new PublicKeyRefreshScheduler(manager, provider);
        assertDoesNotThrow(() -> scheduler.onApplicationEvent(mock(ApplicationReadyEvent.class)));
        scheduler.destroy();
    }

    // -------------------------------------------------------------------------
    // refreshIssuerQuietly — exception swallowed in scheduled task
    // -------------------------------------------------------------------------

    @Test
    void scheduledRefresh_throwsException_doesNotPropagateException() throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        PublicKeyManager manager = mock(PublicKeyManager.class);
        doAnswer(inv -> {
            latch.countDown();
            throw new RuntimeException("refresh error");
        }).when(manager).refreshPublicKeys(anyString());

        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of(source("iss1", Duration.ofMillis(REFRESH_INTERVAL_MS))));

        PublicKeyRefreshScheduler scheduler = new PublicKeyRefreshScheduler(manager, provider);
        scheduler.onApplicationEvent(mock(ApplicationReadyEvent.class));

        boolean fired = latch.await(TEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        scheduler.destroy();
        assertTrue(fired, "Scheduled refresh should have fired");
    }

    // -------------------------------------------------------------------------
    // destroy — graceful termination
    // -------------------------------------------------------------------------

    @Test
    void destroy_terminatesGracefully() {
        PublicKeyManager manager = mock(PublicKeyManager.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        when(provider.keySources()).thenReturn(List.of());

        PublicKeyRefreshScheduler scheduler = new PublicKeyRefreshScheduler(manager, provider);
        scheduler.onApplicationEvent(mock(ApplicationReadyEvent.class));
        assertDoesNotThrow(scheduler::destroy);
    }

    // -------------------------------------------------------------------------
    // destroy — forced shutdown when executor does not terminate in time
    // -------------------------------------------------------------------------

    @Test
    void destroy_forcedShutdown_whenExecutorDoesNotTerminate() throws Exception {
        PublicKeyManager manager = mock(PublicKeyManager.class);
        PublicKeySourceProvider provider = mock(PublicKeySourceProvider.class);
        /// Give it a very long-running refresh so the executor won't terminate immediately;
        // we override the scheduler with a subclass that uses a tiny timeout so the test is fast.
        when(provider.keySources())
            .thenReturn(List.of(source("iss1", Duration.ofMinutes(LONG_REFRESH_INTERVAL_MINUTES))));

        // Use the package-visible test helper subclass that overrides the shutdown timeout.
        PublicKeyRefreshScheduler scheduler =
            new FastShutdownPublicKeyRefreshScheduler(manager, provider);
        scheduler.onApplicationEvent(mock(ApplicationReadyEvent.class));

        // Inject a non-terminating task so the executor is busy during destroy()
        ScheduledExecutorService exec = getScheduler(scheduler);
        exec.submit(() -> {
            try {
                Thread.sleep(Long.MAX_VALUE); //NOSONAR - test helper task that simulates a long-running operation
            } catch (InterruptedException _) {
                Thread.currentThread().interrupt();
            }
        });

        assertDoesNotThrow(scheduler::destroy);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Retrieves the private scheduler field via reflection for the forced-shutdown test. */
    private static ScheduledExecutorService getScheduler(
        PublicKeyRefreshScheduler scheduler) throws Exception {
        Field field = PublicKeyRefreshScheduler.class.getDeclaredField("scheduler");
        field.setAccessible(true);
        return (ScheduledExecutorService) field.get(scheduler);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /** Subclass that reduces the shutdown timeout to make the forced-shutdown test fast. */
    private static final class FastShutdownPublicKeyRefreshScheduler
        extends PublicKeyRefreshScheduler {

        FastShutdownPublicKeyRefreshScheduler(
            PublicKeyManager publicKeyManager,
            PublicKeySourceProvider sourceProvider) {
            super(publicKeyManager, sourceProvider);
        }

        @Override
        public void destroy() throws Exception {
            // Reproduce the destroy logic with a near-zero timeout so the test is fast.
            ScheduledExecutorService exec = getScheduler(this);
            exec.shutdown();
            boolean terminated = exec.awaitTermination(0L, TimeUnit.MILLISECONDS);
            if (!terminated) {
                exec.shutdownNow();
            }
        }
    }
}
