package com.lzk.service;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;
import it.unisa.dia.gas.jpbc.Element;

@Service
public class FileService {

    private static final String ROOT_FOLDER = "root";

    private final AuditService auditService;
    private final CPABEService cpabeService;
    private final AESEncryptionService encryptionService;

    public FileService(AuditService auditService,
                       CPABEService cpabeService,
                       AESEncryptionService encryptionService) {
        this.auditService = auditService;
        this.cpabeService = cpabeService;
        this.encryptionService = encryptionService;
        init();
    }

    private void init() {
        try {
            Files.createDirectories(Paths.get(ROOT_FOLDER));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public List<Map<String, Object>> listRootFoldersNoCheck() {
        auditService.record("SYSTEM", "listRootFoldersNoCheck", "/", true);
        File rootDir = new File(ROOT_FOLDER);
        File[] subs = rootDir.listFiles();
        if (subs == null) return Collections.emptyList();
        return Arrays.stream(subs)
                .filter(File::isDirectory)
                .map(f -> {
                    Map<String, Object> m = new HashMap<>();
                    m.put("name", f.getName());
                    return m;
                })
                .sorted(Comparator.comparing(m -> m.get("name").toString().toLowerCase()))
                .collect(Collectors.toList());
    }

    public List<Map<String, Object>> listFilesInFolder(String folderName, Authentication auth) throws IOException {
        auditService.record(auth.getName(), "openFolder", folderName, true);
        Path folderPath = Paths.get(ROOT_FOLDER, folderName);
        if (!Files.isDirectory(folderPath)) {
            return Collections.emptyList();
        }
        checkFolderRole(folderPath, auth);
        File[] files = folderPath.toFile().listFiles();
        if (files == null) return Collections.emptyList();
        List<Map<String, Object>> result = new ArrayList<>();
        for (File f : files) {
            if (f.isFile() && !f.getName().endsWith(".meta")) {
                Map<String, Object> map = new HashMap<>();
                map.put("folder", folderName);
                map.put("name", f.getName());
                map.put("filename", f.getName());
                map.put("size", f.length());
                result.add(map);
            }
        }
        result.sort(Comparator.comparing(m -> m.get("name").toString().toLowerCase()));
        return result;
    }

    public void createFolder(String folderName, String encryptionAttr, Authentication auth) throws IOException {
        auditService.record(auth.getName(), "createFolder", folderName, true);
        Path folderPath = Paths.get(ROOT_FOLDER, folderName);
        if (Files.exists(folderPath)) {
            throw new IOException("Folder already exists: " + folderName);
        }
        Files.createDirectories(folderPath);
        String metaContent = "allowedRole=" + encryptionAttr +
                "\ncreator=" + auth.getName() +
                "\ncreateTime=" + new Date();
        Files.write(folderPath.resolve(folderName + ".meta"), metaContent.getBytes(StandardCharsets.UTF_8));
    }

    // 加密并保存文件
    public void encryptAndSaveFile(MultipartFile file,
                                   String folderName,
                                   String policy,
                                   String keywords,
                                   Authentication auth) throws Exception {
        auditService.record(auth.getName(), "uploadFile", folderName + "->" + file.getOriginalFilename(), true);
        if (file.isEmpty()) {
            throw new IOException("No file selected");
        }
        Path folderPath = Paths.get(ROOT_FOLDER, folderName);
        if (!Files.isDirectory(folderPath)) {
            throw new IOException("Folder not exist: " + folderName);
        }
        checkFolderRole(folderPath, auth);
        String originalFilename = file.getOriginalFilename();
        String ext = getExtension(originalFilename);
        String randomName = generateRandomString(20) + ext + ".cpabe";
        Path dest = folderPath.resolve(randomName);
        // 生成随机16字节AESKey
        byte[] aesKey16 = new byte[16];
        new Random().nextBytes(aesKey16);
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey16, "AES");
        // AES加密文件内容
        byte[] fileBytes = file.getBytes();
        String cipherTextBase64 = encryptionService.encryptAES(aesKeySpec, new String(fileBytes, StandardCharsets.UTF_8));
        Files.write(dest, cipherTextBase64.getBytes(StandardCharsets.UTF_8));
        // CP-ABE 加密这16字节Key
        CPABEService.Ciphertext ct = cpabeService.encrypt(aesKey16, policy);
        String base64KeyCipher = serializeKeyCipher(ct);
        Properties props = readFolderMeta(folderPath);
        props.setProperty("file." + randomName + ".originalName", originalFilename);
        props.setProperty("file." + randomName + ".keywords", keywords);
        props.setProperty("file." + randomName + ".cpabeKey", base64KeyCipher);
        writeFolderMeta(folderPath, props);
    }

    // 文件搜索
    public List<Map<String, Object>> searchFiles(String folderName, String keywords, Authentication auth) {
        auditService.record(auth.getName(), "search", folderName + "?kw=" + keywords, true);
        List<Map<String, Object>> results = new ArrayList<>();
        try {
            if (folderName == null || folderName.isBlank()) {
                File[] subs = new File(ROOT_FOLDER).listFiles();
                if (subs != null) {
                    for (File f : subs) {
                        if (f.isDirectory()) {
                            try {
                                results.addAll(searchInFolder(f.getName(), keywords, auth));
                            } catch (Exception ignore) {}
                        }
                    }
                }
            } else {
                results.addAll(searchInFolder(folderName, keywords, auth));
            }
        } catch (Exception e) {}
        return results;
    }

    private List<Map<String, Object>> searchInFolder(String folderName, String keywords, Authentication auth) throws IOException {
        Path folderPath = Paths.get(ROOT_FOLDER, folderName);
        if (!Files.isDirectory(folderPath)) return Collections.emptyList();
        checkFolderRole(folderPath, auth);
        Properties props = readFolderMeta(folderPath);
        List<Map<String, Object>> matched = new ArrayList<>();
        // meta-based搜索
        for (String key : props.stringPropertyNames()) {
            if (key.endsWith(".keywords")) {
                String fileKeywords = props.getProperty(key);
                if (fileKeywords != null && fileKeywords.toLowerCase().contains(keywords.toLowerCase())) {
                    String randomName = key.substring("file.".length(), key.length() - ".keywords".length());
                    File f = folderPath.resolve(randomName).toFile();
                    if (f.exists()) {
                        Map<String, Object> m = new HashMap<>();
                        m.put("originalName", props.getProperty("file." + randomName + ".originalName", randomName));
                        m.put("obfuscatedName", randomName);
                        m.put("size", f.length());
                        m.put("matched", true);
                        matched.add(m);
                    }
                }
            }
        }
        // 内容-based搜索
        File[] fs = folderPath.toFile().listFiles();
        if (fs != null) {
            for (File f : fs) {
                if (!f.isDirectory() && !f.getName().endsWith(".meta")) {
                    try {
                        String content = decryptFileContent(folderPath, f.getName(), auth);
                        if (content.toLowerCase().contains(keywords.toLowerCase())) {
                            Map<String, Object> m = new HashMap<>();
                            m.put("name", f.getName());
                            m.put("size", f.length());
                            m.put("matched", true);
                            matched.add(m);
                        }
                    } catch (Exception ignore) {}
                }
            }
        }
        return matched;
    }

    // 查看文件（纯文本）
    public String viewFile(String folderName, String fileName, Authentication auth) throws IOException {
        auditService.record(auth.getName(), "viewFile", folderName + "/" + fileName, true);
        Path filePath = Paths.get(ROOT_FOLDER, folderName, fileName);
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("File not found: " + fileName);
        }
        checkFolderRole(filePath.getParent(), auth);
        return decryptFileContent(filePath.getParent(), fileName, auth);
    }

    // 下载文件
    public void decryptAndDownload(String folderName, String fileName, Authentication auth, HttpServletResponse response) throws IOException {
        auditService.record(auth.getName(), "downloadFile", folderName + "/" + fileName, true);
        Path filePath = Paths.get(ROOT_FOLDER, folderName, fileName);
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("File not found: " + fileName);
        }
        checkFolderRole(filePath.getParent(), auth);
        Properties props = readFolderMeta(filePath.getParent());
        String originalName = props.getProperty("file." + fileName + ".originalName", fileName);
        String content = decryptFileContent(filePath.getParent(), fileName, auth);
        byte[] plainBytes = content.getBytes(StandardCharsets.UTF_8);
        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + originalName + "\"");
        try (OutputStream os = response.getOutputStream()) {
            os.write(plainBytes);
        }
    }

    // 解密核心
    private String decryptFileContent(Path folderPath, String fileName, Authentication auth) throws IOException {
        Properties props = readFolderMeta(folderPath);
        String base64KeyCipher = props.getProperty("file." + fileName + ".cpabeKey");
        if (base64KeyCipher == null) {
            throw new SecurityException("No CP-ABE key found in meta => " + fileName);
        }
        CPABEService.Ciphertext ct = deserializeKeyCipher(base64KeyCipher);
        CPABEService.UserSecretKey usk = getUserSecretKey(auth);
        byte[] aesKey16 = cpabeService.decrypt(ct, usk);
        SecretKeySpec aesKeySpec = new SecretKeySpec(aesKey16, "AES");
        Path filePath = folderPath.resolve(fileName);
        String cipherTextBase64 = Files.readString(filePath);
        try {
            return encryptionService.decryptAES(aesKeySpec, cipherTextBase64);
        } catch (Exception e) {
            throw new SecurityException("AES解密文件失败: " + e.getMessage(), e);
        }
    }

    // 获取用户私钥
    private CPABEService.UserSecretKey getUserSecretKey(Authentication auth) {
        String roleFull = auth.getAuthorities().iterator().next().getAuthority();
        String role = roleFull.replace("ROLE_", "").toLowerCase(Locale.ROOT);
        Set<String> attrs = new HashSet<>();
        attrs.add(role);
        return cpabeService.keygen(attrs);
    }

    private Properties readFolderMeta(Path folderPath) throws IOException {
        Path metaFile = folderPath.resolve(folderPath.getFileName().toString() + ".meta");
        if (!Files.exists(metaFile)) {
            throw new FileNotFoundException("Folder meta not found => " + metaFile);
        }
        Properties props = new Properties();
        try (InputStream is = Files.newInputStream(metaFile)) {
            props.load(is);
        }
        return props;
    }

    private void writeFolderMeta(Path folderPath, Properties props) throws IOException {
        Path metaFile = folderPath.resolve(folderPath.getFileName().toString() + ".meta");
        Properties oldProps = new Properties();
        if (Files.exists(metaFile)) {
            try (InputStream is = Files.newInputStream(metaFile)) {
                oldProps.load(is);
            }
        }
        for (String key : props.stringPropertyNames()) {
            oldProps.setProperty(key, props.getProperty(key));
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        oldProps.store(baos, "folder meta");
        Files.write(metaFile, baos.toByteArray());
    }

    // 文件夹级别权限检查
    private void checkFolderRole(Path folderPath, Authentication auth) throws IOException {
        Properties props = readFolderMeta(folderPath);
        String allowedRole = props.getProperty("allowedRole");
        if (allowedRole == null) {
            throw new SecurityException("No allowedRole in meta => " + folderPath);
        }
        String roleFull = auth.getAuthorities().iterator().next().getAuthority();
        String userRole = roleFull.replace("ROLE_", "").toLowerCase(Locale.ROOT);
        String needed = allowedRole.replace("role=", "");
        if (!userRole.equalsIgnoreCase(needed)) {
            throw new SecurityException("无权限(需要 " + allowedRole + ")!");
        }
    }

    // Ciphertext序列化/反序列化 (会话密钥XOR版本)
    private static String serializeKeyCipher(CPABEService.Ciphertext ct) {
        String policyB64 = Base64.getEncoder().encodeToString(ct.policy.getBytes(StandardCharsets.UTF_8));
        String c0B64 = Base64.getEncoder().encodeToString(ct.c0_bytes);
        byte[] c1Bytes = ct.c1.toBytes();
        String c1B64 = Base64.getEncoder().encodeToString(c1Bytes);
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Element> e : ct.c_attrs.entrySet()) {
            String attr = e.getKey();
            byte[] valBytes = e.getValue().toBytes();
            String valB64 = Base64.getEncoder().encodeToString(valBytes);
            sb.append(attr).append("=").append(valB64).append(";");
        }
        String cAttrsStr = sb.toString();
        String cAttrsB64 = Base64.getEncoder().encodeToString(cAttrsStr.getBytes(StandardCharsets.UTF_8));
        return policyB64 + ":" + c0B64 + ":" + c1B64 + ":" + cAttrsB64;
    }

    private static CPABEService.Ciphertext deserializeKeyCipher(String raw) {
        String[] arr = raw.split(":");
        if (arr.length != 4) {
            throw new RuntimeException("Invalid keyCipher => " + raw);
        }
        CPABEService.Ciphertext ct = new CPABEService.Ciphertext();
        String policy = new String(Base64.getDecoder().decode(arr[0]), StandardCharsets.UTF_8);
        ct.policy = policy;
        byte[] c0 = Base64.getDecoder().decode(arr[1]);
        ct.c0_bytes = c0;
        byte[] c1Bytes = Base64.getDecoder().decode(arr[2]);
        Element c1 = pairingHolder.INSTANCE.getPairing().getG1().newElement();
        c1.setFromBytes(c1Bytes);
        ct.c1 = c1;
        byte[] cAttrDecoded = Base64.getDecoder().decode(arr[3]);
        String cAttrStr = new String(cAttrDecoded, StandardCharsets.UTF_8);
        Map<String, Element> c_attrs = new HashMap<>();
        for (String p : cAttrStr.split(";")) {
            if (p.isBlank()) continue;
            String[] kv = p.split("=");
            String attr = kv[0];
            byte[] valBytes = Base64.getDecoder().decode(kv[1]);
            Element eAttr = pairingHolder.INSTANCE.getPairing().getG1().newElement();
            eAttr.setFromBytes(valBytes);
            c_attrs.put(attr, eAttr);
        }
        ct.c_attrs = c_attrs;
        return ct;
    }

    private static class pairingHolder {
        private static final CPABEService INSTANCE;
        static {
            it.unisa.dia.gas.jpbc.Pairing p =
                    it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory.getPairing("a.properties");
            INSTANCE = new CPABEService(p);
            // 不调用 setup() 只用来 getPairing()
        }
        public static it.unisa.dia.gas.jpbc.Pairing getPairing() {
            return INSTANCE.getPairing();
        }
    }

    private static String generateRandomString(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(ThreadLocalRandom.current().nextInt(chars.length())));
        }
        return sb.toString();
    }

    private static String getExtension(String filename) {
        int idx = filename.lastIndexOf('.');
        return (idx >= 0) ? filename.substring(idx) : "";
    }
}
