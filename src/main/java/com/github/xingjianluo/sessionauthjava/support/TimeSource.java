package com.github.xingjianluo.sessionauthjava.support;

/** Abstraction over the system clock to make time-based logic deterministic in tests. */
public interface TimeSource {
    long nowMillis();
}
