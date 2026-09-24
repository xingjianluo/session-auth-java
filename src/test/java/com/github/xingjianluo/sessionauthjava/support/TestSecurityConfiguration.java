package com.github.xingjianluo.sessionauthjava.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/** Replaces the wall-clock time source with a deterministic one for tests. */
@TestConfiguration(proxyBeanMethods = false)
public class TestSecurityConfiguration {

    @Bean
    @Primary
    public MutableTimeSource mutableTimeSource() {
        return new MutableTimeSource();
    }
}
