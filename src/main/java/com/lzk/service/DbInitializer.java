package com.lzk.service;

import com.lzk.model.User;
import com.lzk.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * 启动时自动检查并添加测试用户
 */
@Component
public class DbInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DbInitializer(UserRepository userRepository,
                         PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.count() == 0) {
            // 数据库为空时添加一些测试用户
            User user0 = new User(null, "lzk",
                    passwordEncoder.encode("123"),
                    "administrator");
            User user1 = new User(null, "wang",
                    passwordEncoder.encode("123"),
                    "contributor");
            User user2 = new User(null, "li",
                    passwordEncoder.encode("123"),
                    "expert");

            userRepository.save(user0);
            userRepository.save(user1);
            userRepository.save(user2);
        }
    }
}

