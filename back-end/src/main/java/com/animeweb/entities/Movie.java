package com.animeweb.entities;
import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "movies")
public class Movie {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;

    @Column(name = "name", columnDefinition = "MEDIUMTEXT")
    private String name;

    @Column(name = "total_chapters")
    private Integer totalChapters;

    @Column(name = "vietnamese_descriptions", columnDefinition = "MEDIUMTEXT")
    private String vietnameseDescriptions;

    @Column(name = "english_descriptions", columnDefinition = "MEDIUMTEXT")
    private String englishDescriptions;

    @Column(name = "create_at",columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Date createAt = new Date();

    @Column(name = "update_at", columnDefinition = "datetime")
    private Date updateAt;

    @Column(name = "delete_at", columnDefinition = "datetime")
    private Date deleteAt;

    @Column(name = "status",columnDefinition = "tinyint default 1")
    private Boolean status = true;

    @Column(name = "producer")
    private String producer;

    @Column(name = "avatar_movie", columnDefinition = "MEDIUMTEXT")
    private String avatarMovie;
    @Column(name = "trailer", columnDefinition = "MEDIUMTEXT")
    private String trailer;
    @Column(name = "series_descriptions", columnDefinition = "MEDIUMTEXT")
    private String seriesDescriptions;
    @ManyToMany(cascade = CascadeType.ALL)
    private List<Genre> genres = new ArrayList<>();
    @OneToMany(mappedBy = "movie",cascade = CascadeType.ALL)
    private List<Chapter> currentChapters = new ArrayList<>();
    @ManyToOne()
    @JoinColumn(name ="serie_id",referencedColumnName = "id")
    private Serie serie;
    @OneToMany(mappedBy = "movie",cascade = CascadeType.ALL)
    private List<View> views =new ArrayList<>();
    @OneToMany(mappedBy = "movie",cascade = CascadeType.ALL)
    private List<Rate> rates = new ArrayList<>();
    @OneToMany(mappedBy = "movie",cascade = CascadeType.ALL)
    private List<Follow> follows = new ArrayList<>();

}
