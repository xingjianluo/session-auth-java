package com.github.xingjianluo.sessionauthjava.controller.dto;

import com.github.xingjianluo.sessionauthjava.document.Document;

/** Client-visible document representation. */
public record DocumentView(String id, String title, String content, String department, String ownerUsername) {
    public static DocumentView of(Document d) {
        return new DocumentView(d.id(), d.title(), d.content(), d.department(), d.ownerUsername());
    }
}
