package com.animeweb.controller.client;

import com.animeweb.dto.movie.FollowDTO;
import com.animeweb.entities.Follow;
import com.animeweb.entities.Movie;
import com.animeweb.entities.User;
import com.animeweb.repository.MovieRepository;
import com.animeweb.repository.UserRepository;
import com.animeweb.service.FollowService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/follow")
public class FollowController {
    @Autowired
    private FollowService followService;
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private MovieRepository movieRepository;


    @PostMapping("/save")
    public ResponseEntity<FollowDTO> followMovie(@RequestBody FollowDTO follow) {
        FollowDTO isFollow;
        User user = userRepository.findById(follow.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found"));
        Movie movie = movieRepository.findById(follow.getMovieId())
                .orElseThrow(() -> new RuntimeException("Movie not found"));
        Follow followEntity = new Follow(follow.getId() != null ? follow.getId() : null, follow.getFollowAt(), follow.getStatus(), user, movie);

        isFollow = followService.addFollow(followEntity);
        return new ResponseEntity<>(isFollow, HttpStatus.CREATED);

    }

    //    @PostMapping("/delete")
//    public ResponseEntity<Void> unFollowMovie(@RequestBody FollowDTO follow) {
//        User user = userRepository.findById(follow.getUserId())
//                .orElseThrow(() -> new RuntimeException("User not found"));
//        Movie movie = movieRepository.findById(follow.getMovieId())
//                .orElseThrow(() -> new RuntimeException("Movie not found"));
//        followService.updateFollow(new Follow(follow.getId(), follow.getFollowAt(), follow.getStatus(), user, movie));
//        return new ResponseEntity<>(HttpStatus.OK);
//    }
    @GetMapping()
    public ResponseEntity<FollowDTO> findFollow(@RequestParam  Long movieId, @RequestParam  Long userId) {
        FollowDTO follow = followService.findFollowByIdUserAndIdMovie(movieId, userId);
        System.out.println("follow "+follow);
        if (follow != null) {

            return new ResponseEntity<>(follow, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.NO_CONTENT);
        }
    }


}