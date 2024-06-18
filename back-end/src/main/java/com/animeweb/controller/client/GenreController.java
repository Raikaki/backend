package com.animeweb.controller.client;

import com.animeweb.dto.genre.GenreDTO;
import com.animeweb.dto.movie.MovieDTO;
import com.animeweb.service.GenreService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/genre")
public class GenreController {
    @Autowired
    GenreService genreService;
    @GetMapping
    public ResponseEntity<List<GenreDTO>> getGenres(){

        return ResponseEntity.ok(genreService.getAllGenre());
    }
    @GetMapping("/movies")
    public ResponseEntity<Map<String,Object>> getMovies(@RequestParam Integer idGenre, @RequestParam(defaultValue = "0") Integer page,
                                                    @RequestParam(defaultValue = "9") Integer size,
                                                    @RequestParam(defaultValue = "createAt") String sortBy,
                                                    @RequestParam(defaultValue = "false") boolean ascending){
        List<MovieDTO> movieDTOS = genreService.getMoviesByGenre(idGenre,page,size,sortBy,ascending);
        Integer total = genreService.totalMoviesByGenresId(idGenre);
        Map<String, Object> response = new HashMap<>();
        response.put("movies", movieDTOS);
        response.put("totalMovies", total);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
