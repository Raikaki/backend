package com.animeweb.service;

import com.animeweb.dto.movie.MovieAdmin;
import com.animeweb.dto.movie.MovieDTO;
import com.animeweb.entities.Movie;
import com.animeweb.entities.View;

import java.util.List;

public interface MovieService {
    void save(Movie movie);
    List<MovieAdmin> getAdminMovie();
    List<MovieDTO> getAllMovie();
    List<MovieDTO> index(int page, int size, String sortBy,boolean ascending);
    List<MovieDTO> findAll();
    MovieDTO findMovieById(Long movieId);
    MovieDTO findMovieWatching(Long movieId);
    List<MovieDTO> searchMovie(String name);
    List<MovieDTO> findAllMovieSameSeries(Long movieId);
    List<MovieDTO> getTopViewDay();
    List<MovieDTO> getTopViewMonth();
    List<MovieDTO> getTopViewYear();
    boolean findByName(String name);
    boolean existById(Long id);
    Movie findById(Long id);
    boolean findByNameNotThis(Long idMovie, String name);
    List<MovieDTO> findAllMovieFollowedByUserId(Long userId);
    void updateView(View view);
    List<MovieDTO> findAllMovieViewedByUserId(Long userId);
}
