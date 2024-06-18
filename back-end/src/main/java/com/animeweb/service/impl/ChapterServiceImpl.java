package com.animeweb.service.impl;

import com.animeweb.dto.chapter.ChapterDTO;
import com.animeweb.entities.Chapter;
import com.animeweb.mapper.ChapterMapper;
import com.animeweb.repository.ChapterRepository;
import com.animeweb.service.ChapterService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class ChapterServiceImpl implements ChapterService {
    @Autowired
    ChapterRepository chapterRepository;
    @Override
    public List<ChapterDTO> getMovieChapters(Long idMovie) {
        List<Chapter> chapters = chapterRepository.findByMovieIdAndStatus(idMovie,true);
        List<ChapterDTO> chapterDTOS = new ArrayList<>();
        for(Chapter chapter : chapters){
            chapterDTOS.add(ChapterMapper.mapToChapterDto(chapter));
        }
        return chapterDTOS;
    }

    @Override
    public List<Chapter> getChapters(Long idMovie) {
        return chapterRepository.findByMovieIdAndStatus(idMovie,true);
    }

    @Override
    public Chapter findById(Long id) {
        return chapterRepository.findByIdAndStatus(id,true);
    }

    @Override
    public boolean isExistOrdinal(Long idMovie, Long id, Integer ordinal) {
        return chapterRepository.existsByMovieIdAndOrdinalAndIdNotAndStatusTrue(idMovie,ordinal,id);
    }

    @Override
    public boolean isExistOrdinal(Long idMovie, Integer ordinal) {
        return chapterRepository.existsByMovieIdAndOrdinalAndStatusTrue(idMovie,ordinal);
    }

    @Override
    public void save(Chapter chapter) {
        chapterRepository.save(chapter);
    }
}
