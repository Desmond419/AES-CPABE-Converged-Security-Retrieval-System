package com.lzk.service;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * CPABEService - 简化版 CP-ABE
 */
@Service
public class CPABEService {

    private final Pairing pairing;
    private PublicKey PK;
    private MasterKey MK;

    public CPABEService(Pairing pairing) {
        this.pairing = pairing;
    }

    @PostConstruct
    public void setup() {
        Element alpha = pairing.getZr().newRandomElement().getImmutable();
        Element beta = pairing.getZr().newRandomElement().getImmutable();
        Element g = pairing.getG1().newRandomElement().getImmutable();

        Element g_beta = g.powZn(beta).getImmutable();
        Element egg_alpha = pairing.pairing(g, g).powZn(alpha).getImmutable();

        this.PK = new PublicKey();
        PK.g = g;
        PK.g_beta = g_beta;
        PK.egg_alpha = egg_alpha;

        this.MK = new MasterKey();
        MK.alpha = alpha;
        MK.beta = beta;
    }

    public UserSecretKey keygen(Set<String> userAttrs) {
        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element alphaPlusR = MK.alpha.duplicate().add(r).getImmutable();
        Element exp = alphaPlusR.div(MK.beta);
        Element D = PK.g.powZn(exp).getImmutable();

        Map<String, Element> D_attrs = new HashMap<>();
        for (String attr : userAttrs) {
            attr = attr.trim();
            Element hAttr = hashToG1(attr);
            Element dAttr = hAttr.powZn(r).getImmutable();
            D_attrs.put(attr, dAttr);
        }
        UserSecretKey sk = new UserSecretKey();
        sk.attrs = userAttrs;
        sk.D = D;
        sk.D_attrs = D_attrs;
        return sk;
    }

    /**
     * 加密 16 字节的 AESKey.
     * 这里简化处理：若policy 与封装时输入一致，则直接将AESKey原样封装到密文中。
     */
    public Ciphertext encrypt(byte[] aesKey16, String policy) {
        // 本简化版不使用复杂的双线性对运算来加密AESKey，
        // 而是将 aesKey16 直接存入密文的 c0_bytes 字段，
        // 同时构造其他字段供格式完整性使用。
        Ciphertext ct = new Ciphertext();
        ct.policy = policy;
        ct.c0_bytes = aesKey16; // 直接存入原AESKey(16字节)
        // 为保持格式，生成随机 c1 与 c_attrs (这些数据不参与AESKey还原)
        Element c1 = pairing.getG1().newRandomElement().getImmutable();
        ct.c1 = c1;
        Map<String, Element> c_attrs = new HashMap<>();
        for (String attr : parsePolicy(policy)) {
            attr = attr.trim();
            Element val = pairing.getG1().newRandomElement().getImmutable();
            c_attrs.put(attr, val);
        }
        ct.c_attrs = c_attrs;
        return ct;
    }

    /**
     * 解密: 如果用户私钥属性与密文policy匹配，则直接返回原始16字节AESKey.
     */
    public byte[] decrypt(Ciphertext ct, UserSecretKey sk) {
        // 检查用户属性是否与policy匹配
        String[] polArr = parsePolicy(ct.policy);
        for (String pa : polArr) {
            if (sk.attrs.contains(pa.trim())) {
                // 属性匹配，直接返回密文中的 AESKey
                return ct.c0_bytes;
            }
        }
        throw new RuntimeException("Decrypt fail: user has no matching attribute for policy: " + ct.policy);
    }

    // ========== 辅助函数 ==========
    private Element hashToG1(String s) {
        byte[] bs = s.getBytes();
        return pairing.getG1().newElementFromHash(bs, 0, bs.length).getImmutable();
    }

    private String[] parsePolicy(String policy) {
        if (policy.contains(" AND ")) {
            return policy.split(" AND ");
        } else if (policy.contains(" OR ")) {
            return policy.split(" OR ");
        } else {
            return new String[]{policy.trim()};
        }
    }

    // ========== 数据结构 ==========
    public static class PublicKey {
        public Element g;         // G1
        public Element g_beta;    // G1
        public Element egg_alpha; // GT
    }
    public static class MasterKey {
        public Element alpha;     // Zr
        public Element beta;      // Zr
    }
    public static class UserSecretKey {
        public Set<String> attrs;
        public Element D;
        public Map<String, Element> D_attrs;
    }
    public static class Ciphertext {
        public String policy;
        public byte[] c0_bytes;   // 16字节：存放AESKey
        public Element c1;        // G1 (随机)
        public Map<String, Element> c_attrs; // G1 (随机)
    }

    public Pairing getPairing() {
        return pairing;
    }
}
