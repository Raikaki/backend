package com.animeweb.mapper;

import com.animeweb.dto.serie.SerieDTO;
import com.animeweb.entities.Serie;
import com.animeweb.service.FormatDate;

import java.util.ArrayList;

public class SerieMapper {

    public static SerieDTO mapToSerieDto(Serie serie){
        return new SerieDTO(serie.getId(),serie.getDescriptions(),new ArrayList<>(), FormatDate.formatDate(serie.getCreateAt()),FormatDate.formatDate(serie.getUpdateAt()),FormatDate.formatDate(serie.getDeleteAt()),serie.getStatus());
    }


}
