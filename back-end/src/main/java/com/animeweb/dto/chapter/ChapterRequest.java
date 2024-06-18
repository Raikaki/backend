package com.animeweb.dto.chapter;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

@NoArgsConstructor
@AllArgsConstructor
@Data
public class ChapterRequest implements Serializable {
    public static Integer URL = 1;
    public static Integer EXCEL = 2;
    public static Integer VIDEO = 3;
    private Integer ordinal;
    private String link;
    private MultipartFile video;
    private Map<Integer, String> excelData = new HashMap<>();
    private Integer type = 1;
}
