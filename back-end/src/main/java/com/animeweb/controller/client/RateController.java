    package com.animeweb.controller.client;


    import com.animeweb.dto.movie.FollowDTO;
    import com.animeweb.dto.movie.RateDTO;
    import com.animeweb.entities.Movie;
    import com.animeweb.entities.Rate;
    import com.animeweb.entities.User;
    import com.animeweb.mapper.MovieMapper;
    import com.animeweb.repository.RatesRepository;
    import com.animeweb.service.MovieService;
    import com.animeweb.service.impl.RateService;
    import com.animeweb.service.impl.UserServiceImpl;
    import org.springframework.beans.factory.annotation.Autowired;
    import org.springframework.http.ResponseEntity;
    import org.springframework.web.bind.annotation.*;

    import java.util.Date;
    import java.util.Optional;

    @RestController
    @RequestMapping("/rates")
    public class RateController {
        @Autowired
        private MovieService movieService;
        @Autowired
        UserServiceImpl userService;

        @Autowired
        private RateService rateService;
        @Autowired
        private RatesRepository rateRepository;
        @GetMapping("/average/{idMovie}")
        public double getAVGRate(@PathVariable Long idMovie) {
            return rateService.getAVGRate(idMovie);
        }

        @GetMapping("/user/{userId}/movie/{movieId}")
        public double getRate(@PathVariable Long userId, @PathVariable Long movieId) {
            return rateService.getRate(userId, movieId);
        }

        @PostMapping("/vote")
        public ResponseEntity<RateDTO> voteMovie(@RequestBody RateDTO rate) { // Use @RequestBody to receive JSON data
            System.out.println(rate);
            User user =userService.findUserById(rate.getUserId());
            Rate findRate = rateRepository.findByUserIdIdAndMovieId(rate.getUserId(), rate.getMovieId()).orElse(null);
            Movie movie = MovieMapper.mapToMovie(movieService.findMovieById(rate.getMovieId())) ;
            if(findRate != null){
                findRate.setUpdateAt(new Date());
                findRate.setScore(rate.getScore());
                rateService.voteMovie(findRate);
            }else{
                Rate rates = new Rate();
                rates.setScore(rate.getScore());
                rates.setUserId(user);
                rates.setMovie(movie);
                Date date = new Date();
                rates.setCreateAt(date);
                rateService.voteMovie(rates);
            }



        return ResponseEntity.ok(rate);
        }



    }


