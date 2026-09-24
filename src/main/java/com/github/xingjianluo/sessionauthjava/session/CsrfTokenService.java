package com.github.xingjianluo.sessionauthjava.session;

import java.security.MessageDigest;
import java.security.SecureRandom;
import org.springframework.stereotype.Component;

/** Generates and compares per-session CSRF synchronizer tokens (constant-time). */
@Component
public class CsrfTokenService {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final char[] ALPHABET =
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".toCharArray();
    private static final int TOKEN_LENGTH = 32;

    /** Generates a 256-bit random URL-safe token. */
    public String generate() {
        char[] buffer = new char[TOKEN_LENGTH];
        for (int i = 0; i < TOKEN_LENGTH; i++) {
            buffer[i] = ALPHABET[RANDOM.nextInt(ALPHABET.length)];
        }
        return new String(buffer);
    }

    /** Constant-time comparison; {@code null} values never match. */
    public boolean matches(String presented, String expected) {
        if (presented == null || expected == null || presented.length() != expected.length()) {
            return false;
        }
        return MessageDigest.isEqual(presented.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                expected.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
