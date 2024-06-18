package com.animeweb.service;

import com.animeweb.dto.chapter.ChapterDTO;
import com.animeweb.entities.Chapter;

import java.util.List;

public interface ChapterService {
    List<ChapterDTO> getMovieChapters(Long idMovie);
    List<Chapter> getChapters(Long idMovie);
    Chapter findById(Long id);
    boolean isExistOrdinal(Long idMovie, Long id, Integer ordinal);
    boolean isExistOrdinal(Long idMovie, Integer ordinal);
    void save(Chapter chapter);
}
