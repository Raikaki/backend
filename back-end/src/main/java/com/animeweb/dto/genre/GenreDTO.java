package com.animeweb.dto.genre;

import com.animeweb.entities.Movie;
import lombok.*;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GenreDTO {
    private Long id;
    private String description;
    private Boolean status;

    public GenreDTO(Long id, String description) {
        this.id = id;
        this.description = description;
    }
}
