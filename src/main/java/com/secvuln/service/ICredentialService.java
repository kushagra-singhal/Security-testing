package com.secvuln.service;

import com.secvuln.entity.Password;
import com.secvuln.entity.User;

import java.security.NoSuchAlgorithmException;
import java.util.List;

public interface ICredentialService {
    List<Password> getPasswordList();

    String hashThePassword(String originalPassword) throws NoSuchAlgorithmException;

    String hashingWithSalt(String originalPassword);

    boolean matchThePassword(String storedHash, String password);

    String bcryptThePassword(String rawPassword);

    List<User> sqlInjection(String username, String password);

    List<User> secureSqlInjection(String username, String password);

}
