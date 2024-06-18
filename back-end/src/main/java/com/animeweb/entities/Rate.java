package com.animeweb.entities;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.util.Date;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "rates")
public class Rate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id ;
    @Column(name= "score")
    private Double score;
    @Column(name = "create_at",columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Date createAt = new Date();
    @Column(name = "update_at", columnDefinition = "datetime")
    private Date updateAt;
    @Column(name = "delete_at", columnDefinition = "datetime")
    private Date deleteAt;
    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name="user_id", referencedColumnName = "id")
    @JsonBackReference
    private User userId;
    @ManyToOne
    @JoinColumn(name ="movie_id",nullable = false,referencedColumnName = "id")
    @JsonBackReference
    private Movie movie;

    public Rate(User userId, Double score, Movie movie, Date createAt) {
        this.userId = userId;
        this.score = score;
        this.movie = movie;
        this.createAt=createAt;
    }
}

