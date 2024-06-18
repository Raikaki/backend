package com.animeweb.entities;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;

import java.util.Date;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "chapters")
public class Chapter {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;
    @Column(name = "ordinal")
    private Integer ordinal;
    @Column(name = "link", columnDefinition = "MEDIUMTEXT")
    private String link;
    @Column(name = "status", columnDefinition = "TINYINT(1)")
    private Boolean status = true;
    @Column(name = "create_at",columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Date createAt = new Date();
    @Column(name = "update_at", columnDefinition = "datetime")
    private Date updateAt;
    @Column(name = "delete_at", columnDefinition = "datetime")
    private Date deleteAt;
    @ManyToOne
    @JoinColumn(name ="movie_id",nullable = false,referencedColumnName = "id")
    @JsonBackReference
    private Movie movie;
}