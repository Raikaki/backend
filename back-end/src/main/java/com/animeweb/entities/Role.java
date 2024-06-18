package com.animeweb.entities;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id ;
    @Column(name= "name", columnDefinition = "MEDIUMTEXT")
    private String name;
    @Column(name="description")
    private String description;
    @Column(name="status",columnDefinition = "tinyint default 1")
    private Boolean status = true;
    @ManyToMany(mappedBy = "roles", cascade = CascadeType.ALL)
    @JsonBackReference
    private List<User> users = new ArrayList<>();
    @ManyToMany
    List<Permission> permissions = new ArrayList<>();
    public Role(Long id, String name) {
        this.id = id;
        this.name = name;
    }
}
