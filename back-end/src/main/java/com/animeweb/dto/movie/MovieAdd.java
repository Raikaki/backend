package com.animeweb.dto.movie;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

import java.io.Serializable;
import java.util.List;
@AllArgsConstructor
@NoArgsConstructor
@Data
public class MovieAdd implements Serializable {
    private String name;
    private Integer totalChapters;
    private String vietnameseDescriptions;
    private String englishDescriptions;
    private String producer;
    private Long series;
    private String trailer;
    private String seriesDescriptions;
    private List<Long> genres;
    private MultipartFile file;
}
