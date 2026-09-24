package com.github.xingjianluo.sessionauthjava.support;

import org.springframework.stereotype.Component;

/** Default {@link TimeSource} backed by {@link System#currentTimeMillis()}. */
@Component
public class SystemTimeSource implements TimeSource {
    @Override
    public long nowMillis() {
        return System.currentTimeMillis();
    }
}
