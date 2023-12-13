package com.secvuln.service;

import com.secvuln.entity.Password;
import com.secvuln.entity.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

@Service
public class CredentialService implements ICredentialService {
    private List<Password> passwordList = new ArrayList<>();
    private int SALT_LENGTH = 16;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public List<Password> getPasswordList() {
        return passwordList;
    }

    @Override
    public String hashThePassword(String originalPassword) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(originalPassword.getBytes());

        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            hexString.append(String.format("%02x", b));
        }
        passwordList.add(new Password(originalPassword, hexString.toString()));
        return hexString.toString();
    }

    @Override
    public String hashingWithSalt(String originalPassword) {
        byte[] salt = generateSalt();
        byte[] combined = concatenateByteArrays(salt, originalPassword.getBytes());
        byte[] hashedPassword = hashWithSHA1(combined);

        passwordList.add(new Password(originalPassword, Base64.getEncoder().encodeToString(concatenateByteArrays(salt, hashedPassword))));
        return Base64.getEncoder().encodeToString(concatenateByteArrays(salt, hashedPassword));
    }

    @Override
    public boolean matchThePassword(String storedHash, String password) {
        byte[] combined = Base64.getDecoder().decode(storedHash);
        byte[] salt = Arrays.copyOfRange(combined, 0, SALT_LENGTH);
        byte[] storedHashedPassword = Arrays.copyOfRange(combined, SALT_LENGTH, combined.length);
        byte[] hashedPasswordToCheck = hashWithSalt(password.getBytes(), salt);

        return MessageDigest.isEqual(storedHashedPassword, hashedPasswordToCheck);
    }

    @Override
    public String bcryptThePassword(String rawPassword) {
        return new BCryptPasswordEncoder().encode(rawPassword);
    }

    @Override
    //    http://localhost:8080/sql-injection?username="qwerty"&password="qwerty" or 1=1
    public List<User> sqlInjection(String username, String password) {
        String sqlQuery = "SELECT * FROM users u where u.username=" + username + "and u.password=" + password;
        return jdbcTemplate.query(sqlQuery, (rs, rowNum) -> {
            User user = new User();
            String usernameVal = rs.getString("username");
            String passwordVal = rs.getString("password");
            user.setId(rowNum);
            user.setUsername(usernameVal);
            user.setPassword(passwordVal);
            return user;
        });
    }

    @Override
    //    http://localhost:8080/secure-sql-injection?username=qwerty&password=qwerty
    public List<User> secureSqlInjection(String username, String password) {
        String sqlQuery = "SELECT * FROM users u where u.username=? and u.password=?";
        return jdbcTemplate.query(sqlQuery, new Object[]{username, password}, (rs, rowNum) -> {
            User user = new User();
            String usernameVal = rs.getString("username");
            String passwordVal = rs.getString("password");
            user.setId(rowNum);
            user.setUsername(usernameVal);
            user.setPassword(passwordVal);
            return user;
        });
    }

    private byte[] hashWithSalt(byte[] password, byte[] salt) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.reset();
            digest.update(salt);
            return digest.digest(password);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error hashing password.", e);
        }
    }

    private byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private byte[] hashWithSHA1(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-1 algorithm not available", e);
        }
    }

    private byte[] concatenateByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }


}
