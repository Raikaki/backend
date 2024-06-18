package com.animeweb.dto.chapter;

import lombok.*;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class ChapterDTO {
    private Long id;
    private Integer ordinal;
    private String link;
    private Boolean status;
    private String createAt;
    private String updateAt;

}
