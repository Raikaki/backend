package com.animeweb.dto.movie;

import com.animeweb.entities.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class MovieAdmin {
    private Long id;
    private String name;
    private Integer totalChapters;
    private String vietnameseDescriptions;
    private String englishDescriptions;
    private String createAt;
    private String updateAt;
    private String deleteAt;
    private Boolean status;
    private String producer;
    private String avatarMovie;
    private String trailer;
    private String seriesDescriptions;
    private String series;
    private List<Genre> genres;
    private Integer currentChapters;
    private Integer views;
    private Integer rates;
    private Integer follows;

}
