package com.animeweb.service.impl;

import com.animeweb.dto.genre.GenreDTO;
import com.animeweb.dto.movie.MovieDTO;
import com.animeweb.entities.Genre;
import com.animeweb.entities.Movie;
import com.animeweb.mapper.GenreMapper;
import com.animeweb.mapper.MovieMapper;
import com.animeweb.repository.GenreRepository;
import com.animeweb.repository.MovieRepository;
import com.animeweb.service.GenreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
@Service
public class GenreServiceImpl implements GenreService {
    @Autowired
    private GenreRepository genreRepository;
    @Autowired
    private MovieRepository movieRepository;
    @Override
    public List<GenreDTO> getAllGenre() {
        List<Genre> genreList = genreRepository.findAllByStatus(true);
        List<GenreDTO> genreDTOList = new ArrayList<>();
        for(Genre genre : genreList){
            genreDTOList.add(GenreMapper.mapToTitleGenreDto(genre));
        }
        return genreDTOList;
    }

    @Override
    public List<MovieDTO> getMoviesByGenre(Integer idGenre,Integer page,Integer size, String sortBy, Boolean ascending) {
        Pageable pageable;

        if (sortBy != null && !sortBy.isEmpty()) {
            Sort.Direction direction = ascending ? Sort.Direction.ASC : Sort.Direction.DESC;
            pageable = PageRequest.of(page, size, direction, sortBy);
        } else {
            pageable = PageRequest.of(page, size);
        }

        Page<Movie> moviePage = movieRepository.findMoviesByGenresId(idGenre, pageable);
        List<MovieDTO> movieDTOS = new ArrayList<>();
        for (Movie m : moviePage.getContent()) {
            movieDTOS.add(MovieMapper.mapToMovieDTO(m));
        }
        return movieDTOS;
    }

    @Override
    public Integer totalMoviesByGenresId(Integer idGenre) {
        return movieRepository.totalMoviesByGenresId(idGenre);
    }

    @Override
    public List<Genre> findGenresByList(List<Long> genres) {
        return genreRepository.findGenresByIds(genres);
    }

    @Override
    public Boolean existDescription(String description) {
        return genreRepository.existsByDescriptionAndStatusTrue(description);
    }

    @Override
    public void save(Genre genre) {
        genreRepository.save(genre);
    }

    @Override
    public Genre getById(Long genreId) {
        return genreRepository.findGenresByIdAndStatusTrue(genreId);
    }
}
