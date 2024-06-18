package com.animeweb.repository;

import com.animeweb.entities.Chapter;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ChapterRepository extends JpaRepository<Chapter, Long> {
    List<Chapter> findByMovieIdAndStatus(Long idMovie,boolean status);
    Chapter findByIdAndStatus(Long id,boolean status);
    Boolean existsByMovieIdAndOrdinalAndIdNotAndStatusTrue(Long idMovie,Integer ordinal,Long id);
    Boolean existsByMovieIdAndOrdinalAndStatusTrue(Long idMovie,Integer ordinal);
}
