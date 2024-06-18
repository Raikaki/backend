package com.animeweb.dto.serie;

import com.animeweb.entities.Movie;
import lombok.*;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SerieDTO {
    private Long id;
    private String descriptions;
    private List<Movie> movieSet;
    private String createAt;
    private String updateAt;
    private String deleteAt;
    private Boolean status;
}
