package com.animeweb.service.impl;

import com.animeweb.dto.movie.MovieAdmin;
import com.animeweb.dto.movie.MovieDTO;
import com.animeweb.entities.Genre;
import com.animeweb.entities.Movie;
import com.animeweb.entities.View;
import com.animeweb.exception.ResourceNotFoundException;
import com.animeweb.mapper.MovieMapper;
import com.animeweb.repository.GenreRepository;
import com.animeweb.repository.MovieRepository;
import com.animeweb.repository.SerieRepository;
import com.animeweb.repository.ViewRepository;
import com.animeweb.service.ChapterService;
import com.animeweb.service.GenreService;
import com.animeweb.service.MovieService;
import com.animeweb.service.SerieService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

@Service
public class MovieServiceImpl implements MovieService {
    @Autowired
    private MovieRepository movieRepository;
    @Autowired
    ViewRepository viewRepository;
    @Autowired
    private GenreRepository genreRepository;
    @Autowired
    private SerieRepository serieRepository;
    @Autowired
    private SerieService serieService;
    @Autowired
    private ChapterService chapterService;
    @Override
    public void save(Movie movie) {
        movieRepository.save(movie);
    }

    @Override
    public List<MovieAdmin> getAdminMovie() {
        List<Movie> movieList = movieRepository.findAll();
        List<MovieAdmin> movieDTOList = new ArrayList<>();
        for (Movie movie : movieList) {
            movie.setGenres(genreRepository.getMovieGenre(movie.getId()));
            movie.setCurrentChapters(chapterService.getChapters(movie.getId()));
           if(movie.getSerie()!=null) {movie.setSerie(serieService.findById(movie.getSerie().getId()));}
            movieDTOList.add(MovieMapper.mapToMovieAdmin(movie));
        }
        return movieDTOList;
    }

    @Override
    public List<MovieDTO> getAllMovie() {
        List<Movie> movieList = movieRepository.findAll();
        List<MovieDTO> movieDTOList = new ArrayList<>();
        for (Movie movie : movieList) {
            movie.setGenres(genreRepository.getMovieGenre(movie.getId()));
            movie.setCurrentChapters(chapterService.getChapters(movie.getId()));
            if(movie.getSerie()!=null) {movie.setSerie(serieService.findById(movie.getSerie().getId()));}
            movieDTOList.add(MovieMapper.mapToMovieDTO(movie));
        }
        return movieDTOList;
    }

    @Override
    public List<MovieDTO> index(int page, int size, String sortBy, boolean ascending) {
        if (sortBy == null || sortBy.isEmpty()) {
            sortBy = "createAt";
        }

        Pageable pageable;
        if (ascending) {
            pageable = PageRequest.of(page, size, Sort.by(sortBy).ascending());
        } else {
            pageable = PageRequest.of(page, size, Sort.by(sortBy).descending());
        }

        Page<Movie> moviePage = movieRepository.findAll(pageable);

        List<MovieDTO> movieDTOS = new ArrayList<>();
        for (Movie m : moviePage.getContent()) {
                m.setGenres(genreRepository.getMovieGenre(m.getId()));
                m.setCurrentChapters(chapterService.getChapters(m.getId()));
                if (m.getSerie() != null) {
                    m.setSerie(serieService.findById(m.getSerie().getId()));
                }
            movieDTOS.add(MovieMapper.mapToMovieDTO(m));
        }
        return movieDTOS;
    }

    @Override
    public List<MovieDTO> findAll() {
        List<Movie> list = movieRepository.findAll();
        List<MovieDTO> movieDTOS = new ArrayList<>();
        for (Movie m : list) {
                m.setGenres(genreRepository.getMovieGenre(m.getId()));
                m.setCurrentChapters(chapterService.getChapters(m.getId()));
                if (m.getSerie() != null) {
                    m.setSerie(serieService.findById(m.getSerie().getId()));
                }
            movieDTOS.add(MovieMapper.mapToMovieDTO(m));
        }
        return movieDTOS;
    }


    @Override
    public MovieDTO findMovieById(Long movieId) {
        Movie movie = movieRepository.findById(movieId).orElse(null);
        if(movie!=null){
        movie.setGenres(genreRepository.getMovieGenre(movie.getId()));
        movie.setCurrentChapters(chapterService.getChapters(movie.getId()));
        if(movie.getSerie()!=null) {movie.setSerie(serieService.findById(movie.getSerie().getId()));}
        return MovieMapper.mapToMovieDTO(movie);
        }else{
            return null;
        }

    }

    @Override
    public MovieDTO findMovieWatching(Long movieId) {
        Movie movie = movieRepository.findMovieWatching(movieId);
        if(movie!=null) {
            movie.setGenres(genreRepository.getMovieGenre(movie.getId()));
            movie.setCurrentChapters(chapterService.getChapters(movie.getId()));
            if (movie.getSerie() != null) {
                movie.setSerie(serieService.findById(movie.getSerie().getId()));
            }
        }
        return MovieMapper.mapToMovieWatching(movie);
    }

    @Override
    public List<MovieDTO> searchMovie(String name) {
        List<Movie> movieList = movieRepository.findByNameContainingIgnoreCase(name, PageRequest.of(0, 5));
        List<MovieDTO> movieDTOList = new ArrayList<>();
        for (Movie movie : movieList) {
            movieDTOList.add(MovieMapper.mapToMovieDTO(movie));
        }
        return movieDTOList;
    }

    @Override
    public List<MovieDTO> getTopViewDay() {
        List<Movie> topMovies = movieRepository.findTopMoviesByDate();
        List<MovieDTO> movieDTOS = new ArrayList<>();

        for (Movie m : topMovies
        ) {
            movieDTOS.add(MovieMapper.mapToMovieDTO(m));
        }
        return movieDTOS;
    }

    @Override
    public List<MovieDTO> getTopViewMonth() {
        List<Movie> topMovies = movieRepository.findTopMoviesMonth();
        List<MovieDTO> movieDTOS = new ArrayList<>();

        for (Movie m : topMovies
        ) {
            movieDTOS.add(MovieMapper.mapToMovieDTO(m));
        }
        return movieDTOS;
    }

    @Override
    public List<MovieDTO> getTopViewYear() {
        List<Movie> topMovies = movieRepository.findTopMoviesYear();
        List<MovieDTO> movieDTOS = new ArrayList<>();

        for (Movie m : topMovies
        ) {
            movieDTOS.add(MovieMapper.mapToMovieDTO(m));
        }
        return movieDTOS;
    }

    @Override
    public boolean findByName(String name) {
        return movieRepository.existsByNameAndStatus(name, true);
    }
    @Override
    public boolean findByNameNotThis(Long idMovie, String name) {
        return movieRepository.existsByNameAndStatusTrueAndIdNot(name, idMovie);
    }

    @Override
    public boolean existById(Long id) {
        return movieRepository.existsById(id);
    }

    @Override
    public Movie findById(Long id) {
        return movieRepository.findMovieByIdAndStatusTrue(id);
    }



    @Override
    public List<MovieDTO> findAllMovieSameSeries(Long movieId) {
        Movie movieS = movieRepository.findById(movieId).orElseThrow(() -> new ResourceNotFoundException("Not found"));
        if (movieS.getSerie() == null) {
            return new ArrayList<>();
        }
        List<Movie> movieList = movieRepository.findAllSeries(movieId, movieS.getSerie().getId());
        List<MovieDTO> movieDTOList = new ArrayList<>();
        for (Movie movie : movieList) {
            movieDTOList.add(MovieMapper.mapToMovieSameSeries(movie));
        }
        return movieDTOList;
    }

    @Override
    public List<MovieDTO> findAllMovieFollowedByUserId(Long userId) {
        List<MovieDTO> result = new ArrayList<>();
        List<Movie> follows = movieRepository.findAllMovieFollowedByUserId(userId);
        for (Movie f : follows) {
            result.add(MovieMapper.mapToMovieDTO(f));
        }
        return result;

    }

    @Override
    public void updateView(View view) {
        viewRepository.save(view);
    }

    @Override
    public List<MovieDTO> findAllMovieViewedByUserId(Long userId) {
        List<MovieDTO> movieDTOS = new ArrayList<>();
        LocalDate now = LocalDate.now();
        LocalDate oneMonthAgo = now.minusMonths(1);

        List<Movie> movies = movieRepository.findAllMovieViewedByUserId(userId);
        for (Movie m : movies
        ){
          movieDTOS.add(MovieMapper.mapToMovieDTO(m))  ;
        }
        return movieDTOS;
    }
}
