package com.github.xingjianluo.sessionauthjava.support;

/** Test-controllable clock: time only advances when a test explicitly moves it. */
public class MutableTimeSource implements TimeSource {

    private volatile long now = 1_000_000L;

    @Override
    public long nowMillis() {
        return now;
    }

    public void set(long millis) {
        this.now = millis;
    }

    public void advanceMillis(long delta) {
        this.now += delta;
    }
}
