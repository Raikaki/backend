package com.animeweb.dto.movie;

import com.animeweb.entities.Movie;
import com.animeweb.entities.User;
import lombok.*;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RateDTO {
    private Long id ;
    private Double score;
    private Date createAt;
    private Date updateAt;
    private Date deleteAt;
    private Long userId;
    private Long movieId;


    public RateDTO(Long userId, Double score, Long movie, Date createAt) {
        this.userId = userId;
        this.score = score;
        this.movieId = movie;
        this.createAt = createAt;
    }
}
