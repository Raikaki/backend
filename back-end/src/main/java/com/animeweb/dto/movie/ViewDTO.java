package com.animeweb.dto.movie;

import com.animeweb.entities.Movie;
import com.animeweb.entities.User;
import lombok.*;

import java.util.Date;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class ViewDTO {
    private Long id;
    private User userId;
    private Movie movie;
    private Date watchAt;
}
