package com.animeweb.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "permissions")
public class Permission {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id ;
    @Column(name= "name", columnDefinition = "MEDIUMTEXT")
    private String name;
    @Column(name="description", columnDefinition = "MEDIUMTEXT")
    private String description;
}
