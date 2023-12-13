package com.secvuln.controller;

import com.secvuln.entity.Password;
import com.secvuln.entity.User;
import com.secvuln.service.CredentialService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.util.List;

@RestController
public class CredentialController {
    @Autowired
    CredentialService credentialService;

    @GetMapping
    public List<Password> getPasswordList() {
        return credentialService.getPasswordList();
    }

    //    assignment: 1
    @GetMapping("hash-the-password")
    public String hashThePassword(@RequestParam String originalPassword) throws NoSuchAlgorithmException {
        return credentialService.hashThePassword(originalPassword);
    }

    //    assignment: 2
    @GetMapping("hashing-with-salt")
    public String hashingWithSalt(@RequestParam String originalPassword) throws NoSuchAlgorithmException {
        return credentialService.hashingWithSalt(originalPassword);
    }

    //    assignment: 3
    @GetMapping("match-the-password")
    public boolean matchThePassword(@RequestParam String hashedPassword, @RequestParam String rawPassword) {
        return credentialService.matchThePassword(hashedPassword, rawPassword);
    }

    //    assignment: 4
    @GetMapping("bcrypt-the-password")
    public String bcryptThePassword(@RequestParam String rawPassword) {
        return credentialService.bcryptThePassword(rawPassword);
    }

    //    assignment: 5
    @GetMapping("sql-injection")
    public List<User> sqlInjection(@RequestParam String username, @RequestParam String password) {
        return credentialService.sqlInjection(username, password);
    }

    //    assignment: 6
    @GetMapping("secure-sql-injection")
    public List<User> secureSqlInjection(@RequestParam String username, @RequestParam String password) {
        return credentialService.secureSqlInjection(username, password);
    }

}
