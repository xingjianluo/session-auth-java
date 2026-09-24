package com.github.xingjianluo.sessionauthjava.tests;

import org.junit.jupiter.api.Test;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** End-to-end smoke test: login, CSRF-protected access and security headers. */
class LoginSmokeTest extends AbstractApiTest {

    @Test
    void loginThenReadDocumentCarriesSecurityHeadersAndCsrf() throws Exception {
        SessionTokens tokens = login("bob", "bob123");

        mockMvc.perform(get("/api/documents/d-sales-1")
                        .cookie(new jakarta.servlet.http.Cookie("SID", tokens.sid())))
                .andDo(r -> testLog.info("INPUT cross-dept GET token={} path={}", tokens.sid().substring(0, 6),
                        r.getRequest().getRequestURI()))
                .andExpect(status().isNotFound())
                .andExpect(content().json("{\"code\":\"NOT_FOUND\"}"));

        mockMvc.perform(get("/api/documents/d-sales-1")
                        .cookie(new jakarta.servlet.http.Cookie("SID", tokens.sid())))
                .andExpect(result -> testLog.info("JUDGEMENT cross-dept status={} body={}",
                        result.getResponse().getStatus(), result.getResponse().getContentAsString()))
                .andExpect(header().exists("X-Frame-Options"))
                .andExpect(header().exists("Content-Security-Policy"));
    }

    @Test
    void stateChangingRequestWithoutCsrfTokenIsRejected() throws Exception {
        SessionTokens tokens = login("bob", "bob123");
        mockMvc.perform(post("/api/documents")
                        .cookie(new jakarta.servlet.http.Cookie("SID", tokens.sid()))
                        .contentType("application/json")
                        .content("{\"title\":\"x\",\"content\":\"y\",\"department\":\"ENG\"}"))
                .andDo(r -> testLog.info("INPUT POST without CSRF path={}", r.getRequest().getRequestURI()))
                .andExpect(result -> testLog.info("JUDGEMENT no-csrf status={} body={}",
                        result.getResponse().getStatus(), result.getResponse().getContentAsString()))
                .andExpect(status().isForbidden())
                .andExpect(content().json("{\"code\":\"CSRF_INVALID\"}"));
    }
}
