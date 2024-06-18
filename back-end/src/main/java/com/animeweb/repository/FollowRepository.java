package com.animeweb.repository;

import com.animeweb.entities.Follow;
import com.animeweb.entities.Movie;
import com.animeweb.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface FollowRepository extends JpaRepository<Follow,Long> {
    @Query("select f from Follow f where f.movie.id = :movie_id and f.userId.id = :user_id")
    Follow findFollowByUserIdAndMovieId(@Param("movie_id") Long movieId,
                                        @Param("user_id") Long userId);


}