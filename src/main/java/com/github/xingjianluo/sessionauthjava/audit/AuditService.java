package com.github.xingjianluo.sessionauthjava.audit;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Stores and logs every authorization decision together with the full evidence that
 * produced it: principal, resource attributes, matched rule, rule-set version and
 * settings version. The bounded in-memory trail supports admin inspection and tests;
 * versioned rules/settings make historical decisions reproducible.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger("AUTHZ_AUDIT");
    private static final int MAX_EVENTS = 2000;

    private final ConcurrentLinkedDeque<AuthorizationEvent> events = new ConcurrentLinkedDeque<>();

    /** Appends the event to the bounded trail and prints the key inputs and decision basis. */
    public void record(AuthorizationEvent event) {
        events.addLast(event);
        while (events.size() > MAX_EVENTS) {
            events.pollFirst();
        }
        log.info("AUTHZ decision={} reason={} user={} role={} token={} {} {} rule={} profile={} "
                        + "ruleVersion={} settingsVersion={} principalAttrs={} resourceAttrs={}",
                event.decision(),
                event.denyReason() == null ? "-" : event.denyReason(),
                event.username(),
                event.role() == null ? "-" : event.role(),
                event.sessionToken() == null ? "-" : com.github.xingjianluo.sessionauthjava.session
                        .SessionManager.mask(event.sessionToken()),
                event.method(),
                event.path(),
                event.matchedRuleId() == null ? "-" : event.matchedRuleId(),
                event.ruleProfile() == null ? "-" : event.ruleProfile(),
                event.ruleVersion(),
                event.settingsVersion(),
                event.principalAttributes(),
                event.resourceAttributes());
    }

    public List<AuthorizationEvent> recent(int limit) {
        return events.stream().skip(Math.max(0, events.size() - limit)).toList();
    }

    public List<AuthorizationEvent> findByPath(String path) {
        return events.stream().filter(e -> path.equals(e.path())).toList();
    }

    public List<AuthorizationEvent> findByUser(String username) {
        return events.stream().filter(e -> username.equals(e.username())).toList();
    }

    public Stream<AuthorizationEvent> stream() {
        return events.stream();
    }

    public void clear() {
        events.clear();
    }
}
