package com.animeweb.controller.client;


import com.animeweb.dto.movie.MovieDTO;
import com.animeweb.dto.movie.ViewDTO;
import com.animeweb.entities.Movie;
import com.animeweb.entities.User;
import com.animeweb.entities.View;
import com.animeweb.security.IntrospectRequest;
import com.animeweb.security.JwtGenerator;
import com.animeweb.security.LogOutRequest;
import com.animeweb.service.MovieService;
import com.animeweb.service.impl.CloudinaryService;
import com.animeweb.service.impl.UserPackedServiceImpl;
import com.animeweb.service.impl.UserServiceImpl;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/movie")
public class MovieController {
    @Autowired
    private MovieService movieService;
    @Autowired
    JwtGenerator jwtGenerator;
    @Autowired
    UserServiceImpl userService;
    @Autowired
    UserPackedServiceImpl userPackedService;
    @Autowired
    CloudinaryService imageService;
    @GetMapping("/index")
    public ResponseEntity<Map<String, Object>> getMovies(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "9") int size,
            @RequestParam(defaultValue = "createAt") String sortBy,
            @RequestParam(defaultValue = "false") boolean ascending) {

        List<MovieDTO> movies = movieService.index(page, size, sortBy, ascending);
        int totalMovies = movieService.findAll().size();
        Map<String, Object> response = new HashMap<>();
        response.put("movies", movies);
        response.put("totalMovies", totalMovies);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/{movieId}")
    public ResponseEntity<MovieDTO> findMovieById(@PathVariable Long movieId) {
        return ResponseEntity.ok(movieService.findMovieById(movieId));
    }
    @GetMapping("/viewed")
    public ResponseEntity<List<MovieDTO>> findMovieViewedByUser(@RequestParam("idUser") Long idUser) {
        List<MovieDTO> movies = movieService.findAllMovieViewedByUserId(idUser);
        return ResponseEntity.ok(movies);
    }
    @PostMapping("/{movieId}")
    public void updateView(@RequestBody IntrospectRequest introspectRequest, @PathVariable Long movieId) throws ParseException {
        SignedJWT verified = jwtGenerator.verifyToken(introspectRequest.getToken(),false);
        Long idUser = verified.getJWTClaimsSet().getLongClaim("idUser");
        View view = new View();
        User user = userService.findUserById(idUser);
        Movie movie = movieService.findById(movieId);
        view.setUserId(user);
        view.setMovie(movie);
        movieService.updateView(view);
    }
    @GetMapping("/watching")
    public ResponseEntity<MovieDTO> findMovieWatching(@RequestParam Long movieId, @RequestParam String token) throws ParseException {
        SignedJWT signedJWT = jwtGenerator.verifyToken(token,false);
        Long idUser = (Long) signedJWT.getJWTClaimsSet().getClaim("idUser");
        User user = userService.findUserById(idUser);
        boolean isBought = userPackedService.checkUserBuyedService(user);
        if (isBought) {
            return ResponseEntity.ok(movieService.findMovieWatching(movieId));
        } else {
            return ResponseEntity.ok().body(null);
        }
    }

    @GetMapping("/search")
    public ResponseEntity<List<MovieDTO>> search(@RequestParam("term") String keyword) {
        List<MovieDTO> movieList = movieService.searchMovie(keyword);

        return new ResponseEntity<>(movieList, HttpStatus.OK);
    }

    @GetMapping("/top-view")
    public ResponseEntity<Map<String, Object>> getTopMovies(@RequestParam("type") String type) {
        Map<String, Object> response = new HashMap<>();
        if ("day".equals(type)) {
            List<MovieDTO> topMovies = movieService.getTopViewDay();
            response.put("topMovies", topMovies);
        } else if ("month".equals(type)) {
            List<MovieDTO> topMovies = movieService.getTopViewMonth();
            response.put("topMovies", topMovies);
        } else if ("year".equals(type)) {
            List<MovieDTO> topMovies = movieService.getTopViewYear();
            response.put("topMovies", topMovies);
        }

        return ResponseEntity.ok(response);
    }

    @GetMapping("/same/{movieId}")
    public ResponseEntity<List<MovieDTO>> getSeries(@PathVariable Long movieId) {
        return ResponseEntity.ok(movieService.findAllMovieSameSeries(movieId));
    }
    @GetMapping("findAll")
    public ResponseEntity<List<MovieDTO>> FindAllMovieFollowed(@RequestParam Long userId) {
        List<MovieDTO> listMovies;
        listMovies=movieService.findAllMovieFollowedByUserId(userId);
        if(listMovies==null){
            return new ResponseEntity<>(null,HttpStatus.NOT_FOUND);
        }
        return new ResponseEntity<>(listMovies,HttpStatus.FOUND);

    }
}
