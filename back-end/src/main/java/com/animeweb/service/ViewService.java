package com.animeweb.service;

import com.animeweb.entities.Movie;
import java.util.List;
public interface ViewService {
     List<Movie>GetTop5MovieViewedByYear();
     List<Movie>GetTop5MovieViewedByMonth();

}
