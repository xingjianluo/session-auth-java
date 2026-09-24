package com.github.xingjianluo.sessionauthjava.document;

import com.github.xingjianluo.sessionauthjava.authz.ResourceAttributeProvider;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Loads document attributes for ABAC rule evaluation. A return value of {@code null}
 * signals a missing document; the authorization layer treats that identically to an
 * attribute denial for resource-scoped paths so existence cannot be probed.
 */
@Component
public class DocumentAttributeProvider implements ResourceAttributeProvider {

    private static final Pattern ITEM_PATH = Pattern.compile("^/api/documents/([^/]+)/?$");

    private final DocumentRepository repository;

    public DocumentAttributeProvider(DocumentRepository repository) {
        this.repository = repository;
    }

    @Override
    public boolean supports(String path, String method) {
        return path != null && ITEM_PATH.matcher(path).find();
    }

    @Override
    public Map<String, String> loadAttributes(String path, String method) {
        Matcher matcher = ITEM_PATH.matcher(path);
        if (!matcher.find()) {
            return null;
        }
        Document document = repository.findById(matcher.group(1));
        if (document == null) {
            return null;
        }
        return Map.of(
                "id", document.id(),
                "department", document.department(),
                "ownerUsername", document.ownerUsername());
    }
}
