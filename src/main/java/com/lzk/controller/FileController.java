package com.lzk.controller;

import com.lzk.service.FileService;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.io.IOException;
import java.util.List;
import java.util.Map;

@Controller
public class FileController {

    @Autowired
    private FileService fileService;

    @GetMapping("/welcome")
    public String welcome(Model model, Authentication authentication,
                          @ModelAttribute("errorMsg") String errorMsg) {
        // 这里“errorMsg”来自 redirect时 addFlashAttribute
        model.addAttribute("errorMsg", errorMsg);
        // 不再检查权限 => 显示所有文件夹
        List<Map<String, Object>> folderList = fileService.listRootFoldersNoCheck();
        model.addAttribute("folders", folderList);
        model.addAttribute("user", authentication.getName());
        return "welcome";
    }

    @GetMapping("/open_folder/{folderName}")
    public String openFolder(@PathVariable("folderName") String folderName,
                             Model model,
                             RedirectAttributes ra,
                             Authentication authentication) {
        try {
            // 这里才做权限检查
            List<Map<String, Object>> fileList = fileService.listFilesInFolder(folderName, authentication);
            model.addAttribute("folderName", folderName);
            model.addAttribute("files", fileList);
        } catch (SecurityException e) {
            ra.addFlashAttribute("errorMsg", "无权限访问：" + folderName + " - " + e.getMessage());
            return "redirect:/welcome";
        } catch (IOException e) {
            ra.addFlashAttribute("errorMsg", "打开文件夹异常：" + e.getMessage());
            return "redirect:/welcome";
        }
        model.addAttribute("user", authentication.getName());
        return "welcome";
    }

    @GetMapping("/fileSearch")
    public String fileSearchPage(Model model, Authentication auth) {
        model.addAttribute("user", auth.getName());
        return "fileSearch";
    }

    @PostMapping("/fileSearch")
    public String fileSearch(@RequestParam("keywords") String keywords,
                             @RequestParam(value = "folder", defaultValue = "") String folderName,
                             Model model,
                             Authentication auth) {
        long start = System.currentTimeMillis();
        List<Map<String, Object>> results = fileService.searchFiles(folderName, keywords, auth);
        long end = System.currentTimeMillis();

        model.addAttribute("results", results);
        model.addAttribute("search_time", (end - start) / 1000.0);
        model.addAttribute("user", auth.getName());
        return "fileSearch";
    }

    @GetMapping("/fileNameEncryption")
    public String fileNameEncryptionPage(Model model, Authentication auth) {
        model.addAttribute("user", auth.getName());
        return "fileNameEncryption";
    }

    @PostMapping("/fileNameEncryption")
    public String fileNameEncryption(@RequestParam("encryption-attribute") String encryptionAttr,
                                     @RequestParam("folder-name") String folderName,
                                     @RequestParam("file-upload") MultipartFile file,
                                     @RequestParam("file-name") String keywords,
                                     Model model,
                                     Authentication auth) {
        try {
            fileService.encryptAndSaveFile(file, folderName, encryptionAttr, keywords, auth);
            model.addAttribute("message", "File encrypted and uploaded successfully.");
        } catch (Exception e) {
            model.addAttribute("message", "Error: " + e.getMessage());
        }
        model.addAttribute("user", auth.getName());
        return "fileNameEncryption";
    }

    @GetMapping("/createFolder")
    public String createFolderPage(Model model, Authentication auth) {
        model.addAttribute("user", auth.getName());
        return "createFolder";
    }

    @PostMapping("/createFolder")
    public String createFolder(@RequestParam("encryption-attribute") String encryptionAttr,
                               @RequestParam("folder-name") String folderName,
                               Model model,
                               Authentication auth) {
        try {
            fileService.createFolder(folderName, encryptionAttr, auth);
            model.addAttribute("message", "Folder created successfully.");
        } catch (Exception e) {
            model.addAttribute("message", "Error: " + e.getMessage());
        }
        model.addAttribute("user", auth.getName());
        return "createFolder";
    }

    @GetMapping("/viewFile/{folderName}/{fileName}")
    public String viewFile(@PathVariable("folderName") String folderName,
                           @PathVariable("fileName") String fileName,
                           Model model,
                           Authentication auth) {
        String content;
        try {
            content = fileService.viewFile(folderName, fileName, auth);
        } catch (Exception e) {
            model.addAttribute("message", "Error: " + e.getMessage());
            return "viewFile";
        }
        model.addAttribute("content", content);
        model.addAttribute("filename", fileName);
        model.addAttribute("user", auth.getName());
        return "viewFile";
    }

    @GetMapping("/readFile")
    public void readFile(@RequestParam("folderName") String folderName,
                         @RequestParam("fileName") String fileName,
                         HttpServletResponse response,
                         Authentication auth) throws IOException {
        try {
            fileService.decryptAndDownload(folderName, fileName, auth, response);
        } catch (SecurityException e) {
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write("<h3>无权限下载: " + e.getMessage() + "</h3>");
        } catch (Exception e) {
            response.setContentType("text/html;charset=UTF-8");
            response.getWriter().write("<h3>下载错误: " + e.getMessage() + "</h3>");
        }
    }

}
