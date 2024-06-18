package com.animeweb.entities;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;
import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "views")
public class View {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;
    @ManyToOne(cascade = CascadeType.ALL)
    @JoinColumn(name="user_id")
    @JsonBackReference
    private User userId;
    @ManyToOne
    @JoinColumn(name ="movie_id",nullable = false,referencedColumnName = "id")
    @JsonBackReference
    private Movie movie;
    @Column(name = "watch_at", columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Date watchAt = new Date();
}
