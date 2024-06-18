package com.animeweb.repository;

import com.animeweb.entities.Movie;
import com.animeweb.entities.View;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
@Repository
public interface ViewRepository extends JpaRepository<View, Long> {
    @Query("select m from View v join Movie m on m.id=v.movie.id where  year(v.watchAt)=year(CURRENT_DATE)" +
            "group by v.movie.id order by  count (v.id) desc limit 5")
    List<Movie> getTop5MovieViewedByYear();
    @Query("select m from View v join Movie m on m.id=v.movie.id where year(v.watchAt)=year(CURRENT_DATE) and month (v.watchAt)=month (CURRENT_DATE)" +
            "group by v.movie.id order by  count (v.id) desc limit 5")
    List<Movie> getTop5MovieViewedByMonth();
}
