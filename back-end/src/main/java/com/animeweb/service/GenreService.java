package com.animeweb.service;

import com.animeweb.dto.genre.GenreDTO;
import com.animeweb.dto.movie.MovieDTO;
import com.animeweb.entities.Genre;

import java.util.List;

public interface GenreService {
    List<GenreDTO> getAllGenre();
    List<MovieDTO> getMoviesByGenre(Integer idGenre,Integer page,Integer size, String sortBy, Boolean ascending);
    Integer totalMoviesByGenresId(Integer idGenre);
    List<Genre> findGenresByList(List<Long> genres);
    Boolean existDescription(String description);
    void save(Genre genre);
    Genre getById(Long genreId);
}
