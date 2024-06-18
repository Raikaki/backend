package com.animeweb.entities;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "follows")
public class Follow {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id ;
    @Column(name = "follow_at",columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Date followAt = new Date();
    @Column(name="status",columnDefinition = "tinyint default 1")
    private Boolean status = true;
    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name="user_id")
    @JsonBackReference
    private User userId;
    @ManyToOne
    @JoinColumn(name ="movie_id",nullable = false,referencedColumnName = "id")
    @JsonBackReference
    private Movie movie;
}
