package com.github.xingjianluo.sessionauthjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.sessionauthjava.audit.AuditService;
import com.github.xingjianluo.sessionauthjava.document.DocumentRepository;
import com.github.xingjianluo.sessionauthjava.login.LoginThrottleService;
import com.github.xingjianluo.sessionauthjava.model.UserDirectory;
import com.github.xingjianluo.sessionauthjava.session.SessionManager;
import com.github.xingjianluo.sessionauthjava.support.MutableTimeSource;
import com.github.xingjianluo.sessionauthjava.support.TestSecurityConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Shared MockMvc setup plus login/cookie/CSRF helpers. */
@SpringBootTest(classes = {com.github.xingjianluo.sessionauthjava.Application.class,
        TestSecurityConfiguration.class})
@AutoConfigureMockMvc
public abstract class AbstractApiTest {

    protected final Logger testLog = LoggerFactory.getLogger(getClass());

    @Autowired
    protected MockMvc mockMvc;
    @Autowired
    protected MutableTimeSource clock;

    @Autowired
    protected ObjectMapper objectMapper;
    @Autowired
    protected SessionManager sessionManager;
    @Autowired
    protected UserDirectory userDirectory;
    @Autowired
    protected DocumentRepository documentRepository;
    @Autowired
    protected LoginThrottleService throttleService;
    @Autowired
    protected AuditService auditService;
    @Autowired
    protected com.github.xingjianluo.sessionauthjava.authz.AccessRuleRegistry ruleRegistry;
    @Autowired
    protected com.github.xingjianluo.sessionauthjava.config.SecurityProperties securityProperties;
    @Autowired
    protected com.github.xingjianluo.sessionauthjava.config.SecurityConfigService configService;

    @BeforeEach
    void resetState() {
        clock.set(1_000_000L);
        // Full in-memory reset: drop all sessions, throttle counters and audit events,
        // then restore the seeded demo data so each test starts from a known baseline.
        for (var user : userDirectory.all()) {
            sessionManager.revokeUser(user.getUsername());
            throttleService.reset(user.getUsername());
        }
        auditService.clear();
        documentRepository.clear();
        userDirectory.all().clear();
        // Restore default security properties and rule profile for a stable baseline.
        securityProperties.getLogin().setMaxSessionsPerUser(2);
        securityProperties.getLogin().setLockThreshold(5);
        securityProperties.getLogin().setLockMillis(300000L);
        securityProperties.getLogin().setRateLimitAttempts(10);
        securityProperties.getLogin().setRateLimitWindowMillis(60000L);
        securityProperties.getLogin().setRateLimitBlockMillis(60000L);
        securityProperties.getSession().setIdleTimeoutMillis(1800000L);
        securityProperties.getCsrf().setEnabled(true);
        configService.reload();
        ruleRegistry.switchProfile(
                com.github.xingjianluo.sessionauthjava.authz.AccessRuleRegistry.PROFILE_DEFAULT);
        seed();
    }

    private void seed() {
        com.github.xingjianluo.sessionauthjava.model.UserAccount admin =
                new com.github.xingjianluo.sessionauthjava.model.UserAccount("admin", "admin123");
        admin.setRole(com.github.xingjianluo.sessionauthjava.model.Role.ADMIN);
        admin.setDepartment("HQ");
        userDirectory.save(admin);
        com.github.xingjianluo.sessionauthjava.model.UserAccount alice =
                new com.github.xingjianluo.sessionauthjava.model.UserAccount("alice", "alice123");
        alice.setRole(com.github.xingjianluo.sessionauthjava.model.Role.MANAGER);
        alice.setDepartment("ENG");
        userDirectory.save(alice);
        com.github.xingjianluo.sessionauthjava.model.UserAccount bob =
                new com.github.xingjianluo.sessionauthjava.model.UserAccount("bob", "bob123");
        bob.setRole(com.github.xingjianluo.sessionauthjava.model.Role.USER);
        bob.setDepartment("ENG");
        userDirectory.save(bob);
        com.github.xingjianluo.sessionauthjava.model.UserAccount carol =
                new com.github.xingjianluo.sessionauthjava.model.UserAccount("carol", "carol123");
        carol.setRole(com.github.xingjianluo.sessionauthjava.model.Role.USER);
        carol.setDepartment("SALES");
        userDirectory.save(carol);

        documentRepository.save(new com.github.xingjianluo.sessionauthjava.document.Document(
                "d-eng-1", "Engineering Handbook", "engineering content", "ENG", "alice"));
        documentRepository.save(new com.github.xingjianluo.sessionauthjava.document.Document(
                "d-sales-1", "Sales Playbook", "sales content", "SALES", "carol"));
    }

    /** Logs in and returns session token + CSRF token, asserting success. */
    protected SessionTokens login(String username, String password) throws Exception {
        String body = objectMapper.writeValueAsString(
                java.util.Map.of("username", username, "password", password));
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json").content(body))
                .andDo(r -> testLog.info("INPUT login user={}", username))
                .andReturn();
        MockHttpServletResponse response = result.getResponse();
        testLog.info("JUDGEMENT login user={} status={} body={}",
                username, response.getStatus(), response.getContentAsString());
        if (response.getStatus() != 200) {
            throw new IllegalStateException("login failed: " + response.getStatus()
                    + " " + response.getContentAsString());
        }
        JsonNode json = objectMapper.readTree(response.getContentAsString());
        String sid = response.getCookie("SID").getValue();
        String csrf = json.get("csrfToken").asText();
        return new SessionTokens(sid, csrf);
    }

    protected record SessionTokens(String sid, String csrf) {
    }
}
