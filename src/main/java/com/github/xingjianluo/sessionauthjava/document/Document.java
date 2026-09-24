package com.github.xingjianluo.sessionauthjava.document;

/** Example protected resource carrying attributes used by ABAC rules. */
public record Document(String id, String title, String content, String department, String ownerUsername) {
}
