package com.lzk.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.*;
import java.util.Base64;

@Service
public class MultiKeyEncryptionService {

    @Value("${aes.multiKeys}")
    private String multiKeysProp; // role:base64key,role2:base64key2,...

    private final Map<String, SecretKeySpec> roleKeyMap = new HashMap<>();

    @PostConstruct
    public void init() {
        // 形如: "administrator:bXlTZWNyZXRLZXkxMjM0NTY2,expert:bXlFeHBlcnRLZXlYWVohQA==,contributor:bXlDb250cmliMTIzNDU2Nzg="
        String[] pairs = multiKeysProp.split(",");
        for (String p : pairs) {
            String[] arr = p.split(":");
            if (arr.length == 2) {
                String role = arr[0].trim();
                String base64Key = arr[1].trim();
                byte[] keyBytes = Base64.getDecoder().decode(base64Key);
                SecretKeySpec spec = new SecretKeySpec(keyBytes, "AES");
                roleKeyMap.put(role.toLowerCase(), spec);
            }
        }
    }

    public byte[] encryptForRole(String role, byte[] plain) {
        SecretKeySpec skey = roleKeyMap.get(role.toLowerCase());
        if (skey == null) {
            throw new RuntimeException("No AES key found for role: " + role);
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skey);
            return cipher.doFinal(plain);
        } catch (Exception e) {
            throw new RuntimeException("encryptForRole failed: " + e.getMessage(), e);
        }
    }

    public byte[] decryptTryAll(byte[] cipher) {
        for (Map.Entry<String, SecretKeySpec> ent : roleKeyMap.entrySet()) {
            try {
                Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
                c.init(Cipher.DECRYPT_MODE, ent.getValue());
                return c.doFinal(cipher);
            } catch (Exception e) {
                // ignore
            }
        }
        throw new RuntimeException("decryptTryAll: no key could decrypt");
    }

    public byte[] decryptByRole(String role, byte[] cipher) {
        SecretKeySpec skey = roleKeyMap.get(role.toLowerCase());
        if (skey == null) {
            throw new RuntimeException("No AES key for role: " + role);
        }
        try {
            Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, skey);
            return c.doFinal(cipher);
        } catch (Exception e) {
            throw new RuntimeException("decryptByRole failed: " + e.getMessage(), e);
        }
    }

    public boolean hasRoleKey(String role) {
        return roleKeyMap.containsKey(role.toLowerCase());
    }
}
