package com.animeweb.mapper;

import com.animeweb.dto.movie.MovieAdd;
import com.animeweb.dto.movie.MovieAdmin;
import com.animeweb.dto.movie.MovieDTO;
import com.animeweb.entities.*;
import com.animeweb.service.FormatDate;

public class MovieMapper {
    public static MovieDTO mapToMovieDTO(Movie movie){
        return new MovieDTO(
                movie.getId(),
                movie.getName(),
                movie.getTotalChapters(),
                movie.getVietnameseDescriptions(),
                movie.getEnglishDescriptions(),
                movie.getCreateAt(),
                movie.getUpdateAt(),
                movie.getDeleteAt(),
                movie.getStatus(),
                movie.getProducer(),
                movie.getAvatarMovie(),
                movie.getTrailer(),
                movie.getSeriesDescriptions(),
                movie.getGenres(),
                movie.getCurrentChapters(),
                movie.getSerie(),
                movie.getViews(),
                movie.getRates(),
                movie.getFollows());
    }
    public static MovieAdmin mapToMovieAdmin(Movie movie){
        return new MovieAdmin(movie.getId(),
                movie.getName(),
                movie.getTotalChapters(),
                movie.getVietnameseDescriptions(),
                movie.getEnglishDescriptions(),
                FormatDate.formatDate(movie.getCreateAt()),
                FormatDate.formatDate(movie.getUpdateAt()),
                FormatDate.formatDate(movie.getDeleteAt()),
                movie.getStatus(),
                movie.getProducer(),
                movie.getAvatarMovie(),
                movie.getTrailer(),
                movie.getSeriesDescriptions(),
                movie.getSerie()!=null?movie.getSerie().getDescriptions():"",
                movie.getGenres(),
                movie.getCurrentChapters().size(),
                movie.getViews().size(),
                movie.getRates().size(),
                movie.getFollows().size()
                );
    }
    public static MovieDTO mapToMovieWatching(Movie movie){
        return new MovieDTO(movie.getId(),movie.getName(),movie.getTotalChapters(),movie.getCurrentChapters());
    }
    public static MovieDTO mapToMovieTopview(Movie movie){
        return new MovieDTO(movie.getId(),movie.getName(),movie.getTotalChapters(),movie.getCurrentChapters());
    }

    public static MovieDTO mapToMovieSameSeries(Movie movie){
        return new MovieDTO(movie.getId(),movie.getName(),movie.getTotalChapters(),
                movie.getCreateAt(),movie.getUpdateAt(),movie.getDeleteAt(),movie.getStatus(),
                movie.getProducer(),movie.getAvatarMovie(),movie.getSeriesDescriptions());
    }
    public static Movie mapToMovie(MovieDTO movieDTO){
        return new Movie(
                movieDTO.getId(),
                movieDTO.getName(),
                movieDTO.getTotalChapters(),
                movieDTO.getVietnameseDescriptions(),
                movieDTO.getEnglishDescriptions(),
                movieDTO.getCreateAt(),
                movieDTO.getUpdateAt(),
                movieDTO.getDeleteAt(),
                movieDTO.getStatus(),
                movieDTO.getProducer(),
                movieDTO.getAvatarMovie(),
                movieDTO.getTrailer(),
                movieDTO.getSeriesDescriptions(),
                movieDTO.getGenres(),
                movieDTO.getCurrentChapters(),
                movieDTO.getSerie(),
                movieDTO.getViews(),
                movieDTO.getRates(),
                movieDTO.getFollows());

    }
    public static Movie mapToMovie(MovieAdd movieAdd) {
        Movie movie = new Movie();
        movie.setName(movieAdd.getName());
        movie.setVietnameseDescriptions(movieAdd.getVietnameseDescriptions());
        movie.setEnglishDescriptions(movieAdd.getEnglishDescriptions());
        movie.setTotalChapters(movieAdd.getTotalChapters());
        movie.setProducer(movieAdd.getProducer());
        movie.setTrailer(movieAdd.getTrailer());
        movie.setSeriesDescriptions(movieAdd.getSeriesDescriptions());
        return movie;
    }

}
