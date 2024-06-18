package com.animeweb.dto.movie;

import com.animeweb.entities.Movie;
import com.animeweb.entities.User;

import lombok.*;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FollowDTO {
    private Long id ;
    private Date followAt;
    private Boolean status;
    private Long userId;
    private Long movieId;




}