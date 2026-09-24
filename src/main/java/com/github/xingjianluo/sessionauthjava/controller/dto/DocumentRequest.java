package com.github.xingjianluo.sessionauthjava.controller.dto;

/** Create/update payload for a document. */
public record DocumentRequest(String title, String content, String department) {
}
