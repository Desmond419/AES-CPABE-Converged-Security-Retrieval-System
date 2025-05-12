# 📁 AES-CPABE融合安全检索系统（AES + 简化 CP-ABE）

> **技术栈** Spring Boot 3 · Spring Security 6 · Spring Data JPA · Thymeleaf 3 · JPBC 2 · MySQL 8 · AES-128  
> **定位** 中小型内网——文件 **内容 + 检索** 同时加密，按「角色属性」精细授权  
---

## 目录
1. [功能概览]  
2. [系统流程]  
3. [运行环境与依赖] 
4. [快速启动]
5. [目录结构]
6. [关键类说明]
7. [加密与权限模型]
8. [页面与路由]
9. [常见问题]
10. [TODO]
11. [参考与致谢]

---
## 功能概览
| 模块             | 说明                                                                 |
|------------------|----------------------------------------------------------------------|
| **账户管理**     | BCrypt 密码；默认三角色：`administrator / expert / contributor`（亦支持自定义） |
| **文件夹创建**   | 指定“加密属性”→ 生成文件夹与 `.meta`（记录 `allowedRole` 等）         |
| **文件上传**     | 浏览器上传 → 随机 AES-128 加密正文 → AES 密钥用 CP-ABE 封装           |
| **文件检索**     | ① `.meta` 关键词匹配 ② 解密全文匹配                                    |
| **文件查看/下载**| 属性匹配成功后解封 AES 密钥 → 解密正文                                 |
| **审计日志**     | 内存 List 记录：时间、用户、动作、目标、是否成功                       |

---
## 系统流程
```text
Browser ⇄ Controller              ⇄ FileService
            │                        ├─ AESEncryptionService (AES/ECB)
            │                        └─ CPABEService         (JPBC 简化 CP-ABE)
MySQL ⇄ Spring Data JPA  (users 表)
FS   root/…  (加密文件 + .meta)
```

---
## 运行环境与依赖
- JDK：17 或以上  
- Maven：3.8+  
- 数据库：MySQL 8.x  
- JPBC：Maven 自动拉取  
- a.properties：Type A 曲线参数  


---
## 快速启动
git clone https://github.com/Desmond419/AES-CPABE-Converged-Security-Retrieval-System.git

1. 准备数据库
mysql -u -p -e "CREATE DATABASE IF NOT EXISTS jsnu_thesis CHARACTER SET utf8mb4;"

2. 复制 JPBC 参数
cp /path/to/a.properties src/main/resources/

3. 运行应用
./mvnw spring-boot:run   # 或 mvn spring-boot:run


---
## 目录结构
```
src/main/java/com/lzk/
 ├─config/         # Spring & JPBC 配置
 ├─controller/     # AuthController / FileController
 ├─model/          # User 实体
 ├─repository/     # UserRepository
 └─service/        # AES / CP-ABE / 文件 / 审计
src/main/resources/
 ├─templates/      # Thymeleaf HTML 页面
 ├─static/         # 前端静态资源 (CSS/JS)
 └─a.properties    # 双线性对参数
root/              # 运行时生成的加密文件根目录
```

---
## 关键类说明
- JPBCConfig：读取 a.properties，注册 Pairing Bean  
- SecurityConfig：表单登录、自定义静态资源放行、关闭 CSRF  
- CPABEService：简化 CP-ABE，用于封装/解封 16 字节 AES Key  
- AESEncryptionService：AES-128 ECB PKCS5Padding 加解密 + Base64  
- FileService：上传/加密/检索/下载/权限校验/元数据维护  
- AuditService：内存审计日志  
- DbInitializer：首次启动插入演示用户  


---
## 加密与权限模型
1. 上传流程
   - 随机生成 16 字节 AES Key
   - AES 加密文件内容 -> 保存为 randomName.ext.cpabe
   - CP-ABE 封装 AES Key (policy = 加密属性)
   - 更新文件夹 .meta: originalName, keywords, cpabeKey, allowedRole

2. 检索流程
   - 先对 .meta 解密并关键词匹配
   - 如需全文搜索则解密正文

3. 查看/下载
   - 生成用户临时私钥 (基于角色属性)
   - 解封 AES Key -> 解密文件 -> 渲染或输出下载

4. 角色自定义
   - 新增用户时可任意指定 role
   - 创建文件夹时写入 allowedRole
   - 其余流程自动适配，无需改动


---
## 页面与路由
```
GET    /login                   -> userlogin.html
POST   /login-process           -> 登录处理
GET    /welcome                 -> welcome.html (根目录/主页)
GET    /createFolder            -> createFolder.html
POST   /createFolder            -> 创建文件夹
GET    /fileNameEncryption      -> fileNameEncryption.html
POST   /fileNameEncryption      -> 加密上传
GET/POST /fileSearch            -> fileSearch.html
GET    /viewFile/{folder}/{file} -> viewFile.html
GET    /readFile                -> 下载解密文件
```


---
## 常见问题
问题：JPBC 参数加载失败<br>
解决：确认 a.properties 在 resources/ 下且格式正确

问题：无法连接 MySQL<br>
解决：检查 application.properties 中的 URL、用户名、密码

问题：无权限访问或下载<br>
解决：确认 .meta 中 allowedRole 与当前用户角色匹配

问题：AES 解密失败<br>
解决：文件内容损坏或 cpabeKey 串被篡改，请重新上传


---
## 参考与致谢
- JPBC Library: https://github.com/sgu-bioinfo/jpbc
- Waters, B. “Ciphertext-Policy Attribute-Based Encryption.” IEEE S&P 2011.
- Spring Security 官方文档
- Bootstrap 5 CDN
---
