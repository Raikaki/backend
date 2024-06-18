package com.animeweb.service;

import com.animeweb.dto.serie.SerieDTO;
import com.animeweb.entities.Serie;

import java.util.List;

public interface SerieService {
    List<SerieDTO> getAllSerie();

    Serie findById(Long id);

    void save(Serie updateSerie);

    boolean findByDescription(String descriptions);
}
