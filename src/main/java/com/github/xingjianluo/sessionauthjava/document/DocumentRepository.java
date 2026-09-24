package com.github.xingjianluo.sessionauthjava.document;

import java.util.Collection;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Repository;

/** In-memory document store keyed by document id. */
@Repository
public class DocumentRepository {

    private final ConcurrentHashMap<String, Document> documents = new ConcurrentHashMap<>();

    public Document findById(String id) {
        if (id == null) {
            return null;
        }
        return documents.get(id);
    }

    public Document save(Document document) {
        documents.put(document.id(), document);
        return document;
    }

    public boolean deleteById(String id) {
        return documents.remove(id) != null;
    }

    public Collection<Document> findAll() {
        return List.copyOf(documents.values());
    }

    public void clear() {
        documents.clear();
    }
}
