package com.github.xingjianluo.sessionauthjava.bootstrap;

import com.github.xingjianluo.sessionauthjava.document.Document;
import com.github.xingjianluo.sessionauthjava.document.DocumentRepository;
import com.github.xingjianluo.sessionauthjava.model.Role;
import com.github.xingjianluo.sessionauthjava.model.UserAccount;
import com.github.xingjianluo.sessionauthjava.model.UserDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/** Seeds demo users (one per role and department combination) and documents. */
@Component
public class DemoDataInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataInitializer.class);

    private final UserDirectory userDirectory;
    private final DocumentRepository documentRepository;

    public DemoDataInitializer(UserDirectory userDirectory, DocumentRepository documentRepository) {
        this.userDirectory = userDirectory;
        this.documentRepository = documentRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        seedUser("admin", "admin123", Role.ADMIN, "HQ");
        seedUser("alice", "alice123", Role.MANAGER, "ENG");
        seedUser("bob", "bob123", Role.USER, "ENG");
        seedUser("carol", "carol123", Role.USER, "SALES");

        documentRepository.save(new Document("d-eng-1", "Engineering Handbook",
                "engineering content", "ENG", "alice"));
        documentRepository.save(new Document("d-sales-1", "Sales Playbook",
                "sales content", "SALES", "carol"));
        log.info("Demo data seeded: users={}, documents={}",
                userDirectory.all().size(), documentRepository.findAll().size());
    }

    private void seedUser(String username, String password, Role role, String department) {
        UserAccount user = new UserAccount(username, password);
        user.setRole(role);
        user.setDepartment(department);
        userDirectory.save(user);
    }
}
