package com.lzk;

import jakarta.annotation.PostConstruct;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.nio.file.Files;
import java.nio.file.Paths;

@SpringBootApplication
public class JsnuFinalThesisApplication {

	public static void main(String[] args) {
		SpringApplication.run(JsnuFinalThesisApplication.class, args);
	}

	@PostConstruct
	public void init() throws Exception {
		// 创建必要目录
		String[] folders = {"root", "metadata", "temp_decrypted"};
		for (String folder : folders) {
			if (!Files.exists(Paths.get(folder))) {
				Files.createDirectories(Paths.get(folder));
			}
		}
	}
}
