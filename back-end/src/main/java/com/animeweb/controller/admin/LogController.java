package com.animeweb.controller.admin;


import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@RestController
    @RequestMapping("/admin/logs")
    public class LogController {

        private static final String LOG_DIR = "logs";
        private static final String LOG_FILE = "spring-boot-application.log";

        @GetMapping
        public List<String> getLogs() throws IOException {

            return Files.readAllLines(Paths.get(LOG_DIR, LOG_FILE));
        }
        @GetMapping("/archive")
            public StreamingResponseBody archiveLogs(@RequestParam String archivePath) throws IOException {
                File logDir = new File(LOG_DIR);
                File[] logFiles = logDir.listFiles((dir, name) -> name.matches("spring-boot-application\\..*\\.log"));

                if (logFiles == null || logFiles.length == 0) {
                    throw new FileNotFoundException("No log files found to archive.");
                }
                File zipFile = new File(archivePath, "logs.zip");
                try (ZipOutputStream zipOut = new ZipOutputStream(new FileOutputStream(zipFile))) {
                    for (File logFile : logFiles) {
                        try (FileInputStream fis = new FileInputStream(logFile)) {
                            ZipEntry zipEntry = new ZipEntry(logFile.getName());
                            zipOut.putNextEntry(zipEntry);
                            byte[] bytes = new byte[1024];
                            int length;
                            while ((length = fis.read(bytes)) >= 0) {
                                zipOut.write(bytes, 0, length);
                            }
                            zipOut.closeEntry();
                        }
                    }
                }

                // Xóa log sau khi lưu trữ
                for (File logFile : logFiles) {
                    Files.delete(logFile.toPath());
                }
                return outputStream -> {
                    try (FileInputStream fis = new FileInputStream(zipFile)) {
                        byte[] buffer = new byte[1024];
                        int length;
                        while ((length = fis.read(buffer)) > 0) {
                            outputStream.write(buffer, 0, length);
                        }
                    }
                };
        }

        @DeleteMapping
        public void deleteLogs() throws IOException {
            File logDir = new File(LOG_DIR);
            File[] logFiles = logDir.listFiles((dir, name) -> name.matches("spring-boot-application\\..*\\.log"));

            if (logFiles != null) {
                for (File logFile : logFiles) {
                    Files.delete(logFile.toPath());
                }
            }
        }
}
