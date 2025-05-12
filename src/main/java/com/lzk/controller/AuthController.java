package com.lzk.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthController {

    // 登录页
    @GetMapping("/login")
    public String loginPage() {
        return "userlogin";  // 对应 templates/userlogin.html
    }
}
