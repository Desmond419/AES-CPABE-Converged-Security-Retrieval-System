package com.lzk.service;

import it.unisa.dia.gas.jpbc.Element;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

/**
 * AES 工具类
 */
@Service
public class AESEncryptionService {

    // AES加密：返回Base64
    public String encryptAES(SecretKeySpec aesKey, String plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // AES解密：传入Base64，返回明文字符串
    public String decryptAES(SecretKeySpec aesKey, String ciphertextBase64) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(ciphertextBase64));
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
