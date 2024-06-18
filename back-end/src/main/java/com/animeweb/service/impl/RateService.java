package com.animeweb.service.impl;

import com.animeweb.entities.Movie;
import com.animeweb.entities.Rate;
import com.animeweb.entities.User;
import com.animeweb.repository.MovieRepository;
import com.animeweb.repository.RatesRepository;
import com.animeweb.repository.UserPackedRepository;
import com.animeweb.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.Optional;

@Service
public class RateService {

    @Autowired
    private RatesRepository rateRepository;
    @Autowired
    private MovieRepository movieRepository;
    @Autowired
    UserRepository userRepository;

    public double getAVGRate(Long idMovie) {
        return rateRepository.findAverageScoreByMovieId(idMovie).orElse(0.0);
    }

    public double getRate(Long userId, Long movieId) {
        Optional<Rate> rate = rateRepository.findByUserIdIdAndMovieId(userId, movieId);
        return rate.map(Rate::getScore).orElse(0.0);
    }


    public void voteMovie(Rate rate) {


        rateRepository.save(rate);
    }


}
