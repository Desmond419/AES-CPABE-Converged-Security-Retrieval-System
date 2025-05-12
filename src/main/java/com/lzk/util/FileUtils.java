package com.lzk.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Random;

public class FileUtils {

    // 读取文件文本内容
    public static String readFileContent(String path) {
        File file = new File(path);
        if (!file.exists()) return "";
        try {
            return new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
            return "";
        }
    }

    // 追加写文件
    public static void appendToFile(String filePath, String content) {
        try (FileWriter fw = new FileWriter(filePath, true)) {
            fw.write(content);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // 从元数据中获取 Original File Name (简化示例)
    public static String getOriginalNameFromMetadata(String encryptedFileName, String metadataContent) {
        if (metadataContent == null || metadataContent.isBlank()) return null;
        if (encryptedFileName == null) return null;

        String[] blocks = metadataContent.split("BLOCK\\s*\\n=====\\s*\\n");
        for (String block : blocks) {
            if (block.contains(encryptedFileName)) {
                // 找 Original File Name
                for (String line : block.split("\\n")) {
                    if (line.startsWith("Original File Name:")) {
                        return line.replace("Original File Name:", "").trim();
                    }
                }
            }
        }
        return null;
    }

    // 随机文件名
    public static String generateRandomString(int length) {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        Random rnd = new Random();
        StringBuilder sb = new StringBuilder(length);
        for(int i=0; i<length; i++){
            sb.append(chars.charAt(rnd.nextInt(chars.length())));
        }
        return sb.toString();
    }
}
