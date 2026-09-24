package com.github.xingjianluo.sessionauthjava.controller;

import com.github.xingjianluo.sessionauthjava.controller.dto.DocumentRequest;
import com.github.xingjianluo.sessionauthjava.controller.dto.DocumentView;
import com.github.xingjianluo.sessionauthjava.document.Document;
import com.github.xingjianluo.sessionauthjava.document.DocumentRepository;
import com.github.xingjianluo.sessionauthjava.model.AuthPrincipal;
import com.github.xingjianluo.sessionauthjava.web.ApiError;
import com.github.xingjianluo.sessionauthjava.web.CurrentUser;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Protected example resource. Authorization (RBAC + ABAC + existence hiding) is enforced
 * centrally by {@code AuthorizationInterceptor}; the controller only handles CRUD.
 * Missing items return 404 identical to an attribute denial at the security layer.
 */
@RestController
@RequestMapping("/api/documents")
public class DocumentController {

    private final DocumentRepository repository;

    public DocumentController(DocumentRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public List<DocumentView> list() {
        return repository.findAll().stream().map(DocumentView::of).toList();
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> get(@PathVariable String id) {
        Document document = repository.findById(id);
        if (document == null) {
            return notFound();
        }
        return ResponseEntity.ok(DocumentView.of(document));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<DocumentView> create(@CurrentUser AuthPrincipal principal,
                                               @RequestBody DocumentRequest body) {
        Document document = new Document(
                UUID.randomUUID().toString(),
                body.title(),
                body.content(),
                body.department() != null ? body.department() : principal.department(),
                principal.username());
        repository.save(document);
        return ResponseEntity.status(HttpStatus.CREATED).body(DocumentView.of(document));
    }

    @PutMapping("/{id}")
    public ResponseEntity<?> update(@PathVariable String id, @RequestBody DocumentRequest body) {
        Document existing = repository.findById(id);
        if (existing == null) {
            return notFound();
        }
        Document updated = new Document(existing.id(), body.title(), body.content(),
                body.department() != null ? body.department() : existing.department(),
                existing.ownerUsername());
        repository.save(updated);
        return ResponseEntity.ok(DocumentView.of(updated));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable String id) {
        if (!repository.deleteById(id)) {
            return notFound();
        }
        return ResponseEntity.noContent().build();
    }

    private ResponseEntity<ApiError> notFound() {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new ApiError("NOT_FOUND", "Resource not found", null));
    }
}
