package com.animeweb.repository;

import com.animeweb.entities.Rate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface RatesRepository extends JpaRepository<Rate, Long> {
    @Query("SELECT AVG(r.score) FROM Rate r WHERE r.movie.id = :idMovie")
    Optional<Double> findAverageScoreByMovieId(@Param("idMovie") Long idMovie);

    Optional<Rate> findByUserIdIdAndMovieId(Long userId, Long movieId);

}
