package com.animeweb.repository;

import com.animeweb.entities.Genre;
import com.animeweb.entities.Serie;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SerieRepository extends JpaRepository<Serie,Long> {

    Optional<Serie> findByIdAndStatus(Long id,boolean status);
    List<Serie> getAllByStatus(boolean status);
    boolean existsByDescriptionsAndStatus(String descriptions,boolean status);
}
