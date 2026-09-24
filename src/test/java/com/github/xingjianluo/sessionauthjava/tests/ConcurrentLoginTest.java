package com.github.xingjianluo.sessionauthjava.tests;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Concurrent login & session-limit scenarios.
 *
 * <p>Evidence logged per case: configured max sessions, per-request result, aggregate
 * counts and the resulting active session count.
 */
class ConcurrentLoginTest extends AbstractApiTest {

    @Test
    void thirdSequentialLoginIsRejectedWithConcurrencyLimit() throws Exception {
        adminConfig(Map.of("maxSessionsPerUser", 2));

        SessionTokens first = login("bob", "bob123");
        SessionTokens second = login("bob", "bob123");
        testLog.info("INPUT two active sessions token1={} token2={}",
                first.sid().substring(0, 6), second.sid().substring(0, 6));

        MvcResult third = rawLogin("bob", "bob123");
        testLog.info("JUDGEMENT third login status={} body={} (maxSessions=2)",
                third.getResponse().getStatus(), third.getResponse().getContentAsString());

        assertEquals(409, third.getResponse().getStatus());
        assertTrue(third.getResponse().getContentAsString().contains("CONCURRENCY_LIMIT"));
    }

    @Test
    void twentyParallelLoginsYieldExactlyMaxSessionsSuccesses() throws Exception {
        adminConfig(Map.of("maxSessionsPerUser", 2));

        int threads = 20;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<MvcResult>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> rawLogin("alice", "alice123"));
        }
        List<Future<MvcResult>> futures = pool.invokeAll(tasks);
        pool.shutdown();
        assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "login tasks should finish");

        int success = 0;
        int limited = 0;
        for (Future<MvcResult> future : futures) {
            MockHttpServletResponse response = future.get().getResponse();
            if (response.getStatus() == 200) {
                success++;
            } else if (response.getContentAsString().contains("CONCURRENCY_LIMIT")) {
                limited++;
            }
        }
        testLog.info("JUDGEMENT parallel logins total={} success={} concurrencyLimited={} maxSessions=2",
                threads, success, limited);
        assertEquals(2, success, "exactly maxSessionsPerUser sessions may be issued");
        assertEquals(threads - 2, limited, "every losing racer must get CONCURRENCY_LIMIT");
    }

    private MvcResult rawLogin(String username, String password) throws Exception {
        String body = objectMapper.writeValueAsString(
                Map.of("username", username, "password", password));
        return mockMvc.perform(post("/api/auth/login")
                .contentType("application/json").content(body)).andReturn();
    }

    private void adminConfig(Map<String, Object> changes) throws Exception {
        SessionTokens admin = login("admin", "admin123");
        String body = objectMapper.writeValueAsString(changes);
        mockMvc.perform(post("/api/admin/config")
                        .cookie(new jakarta.servlet.http.Cookie("SID", admin.sid()))
                        .header("X-CSRF-TOKEN", admin.csrf())
                        .contentType("application/json").content(body))
                .andExpect(r -> org.junit.jupiter.api.Assertions.assertEquals(
                        200, r.getResponse().getStatus(), r.getResponse().getContentAsString()));
    }
}
