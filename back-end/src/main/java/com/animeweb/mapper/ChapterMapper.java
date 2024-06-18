package com.animeweb.mapper;

import com.animeweb.dto.chapter.ChapterDTO;
import com.animeweb.entities.Chapter;
import com.animeweb.service.FormatDate;

public class ChapterMapper {
    public static ChapterDTO mapToChapterDto(Chapter chapter){
        return new ChapterDTO(chapter.getId(),chapter.getOrdinal(),chapter.getLink(),chapter.getStatus(), FormatDate.formatDate(chapter.getCreateAt()),FormatDate.formatDate(chapter.getUpdateAt()));
    }
}
