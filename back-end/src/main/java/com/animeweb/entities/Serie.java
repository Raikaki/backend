package com.animeweb.entities;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "series")
public class Serie {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;
    @Column(name = "descriptions")
    private String descriptions;
    @OneToMany(mappedBy = "serie",cascade = CascadeType.ALL)
    @JsonBackReference
    private List<Movie> movieSet = new ArrayList<>();
    @Column(name = "create_at",columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Date createAt = new Date();

    @Column(name = "update_at", columnDefinition = "datetime")
    private Date updateAt;

    @Column(name = "delete_at", columnDefinition = "datetime")
    private Date deleteAt;
    @Column(name = "status",columnDefinition = "tinyint default 1")
    private Boolean status = true;

}
