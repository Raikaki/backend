package com.animeweb.entities;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "users")
public class User implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;
    @ManyToMany
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id")
    )
    @JsonBackReference
    private List<Role> roles = new ArrayList<>();
    @Column(name = "user_name", length = 500)
    private String userName;
    @Column(name = "avatar_picture", length = 500)
    private String avatarPicture;
    @Column(name = "password", length = 500)
    private String password;
    @Column(name = "email", length = 500)
    private String email;
    @Column(name = "full_name", columnDefinition = "MEDIUMTEXT")
    private String fullName;
    @Column(name = "phone", length = 45)
    private String phone;
    @Column(name = "user_type",  columnDefinition = "int (1)")
    private Integer userType = 1;
    @Column(name = "create_at", columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Date createdAt = new Date();
    @Column(name = "update_at", columnDefinition = "datetime")
    private Date updatedAt;
    @Column(name = "delete_at", columnDefinition = "datetime")
    private Date deletedAt;
    @Column(name = "status", nullable = false, columnDefinition = "TINYINT(1)")
    private Boolean status = true;
    @Column(name = "authCode")
    private String authCode;
    @Column(name = "expired_at", columnDefinition = "datetime")
    private Date expiredAt;
    @Column(name = "authenticated", columnDefinition = "TINYINT(0)")
    private Boolean authenticated = false;
    @Column(name="externalId")
    private String externalId;
    @Column(name = "isActive", nullable = false, columnDefinition = "TINYINT(1)")
    private Boolean isActive = true;
    @OneToMany(mappedBy = "userId",cascade = CascadeType.ALL)
    private List<View> views = new ArrayList<>();
    @OneToMany(mappedBy = "userId",cascade = CascadeType.ALL)
    private List<Rate> rates = new ArrayList<>();
    @OneToMany(mappedBy = "userId",cascade = CascadeType.ALL)
    private List<Follow> follows = new ArrayList<>();
    public User(Long id, String userName, String avatarPicture, String email, String fullName, String phone, Integer userType, Boolean status, String externalId) {
        this.id = id;
        this.userName = userName;
        this.avatarPicture = avatarPicture;
        this.email = email;
        this.fullName = fullName;
        this.phone = phone;
        this.userType = userType;
        this.status = status;
        this.externalId = externalId;
    }

    public User(String userName, String avatarPicture, String email, String fullName, String phone, Integer userType, String externalId) {
        this.userName = userName;
        this.avatarPicture = avatarPicture;
        this.email = email;
        this.fullName = fullName;
        this.phone = phone;
        this.userType = userType;
        this.externalId = externalId;
    }

    public User(String userName, String password, String email, String fullName, String phone) {
        this.userName = userName;
        this.password = password;
        this.email = email;
        this.fullName = fullName;
        this.phone = phone;
    }


    public User( String userName, String avatarPicture, String password, String email, String fullName, String phone, Integer userType, Date createdAt, Date updatedAt, Date deletedAt, Boolean status, String externalId, List<View> views, List<Rate> rates, List<Follow> follows) {

        this.userName = userName;
        this.avatarPicture = avatarPicture;
        this.password = password;
        this.email = email;
        this.fullName = fullName;
        this.phone = phone;
        this.userType = userType;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.deletedAt = deletedAt;
        this.status = status;
        this.externalId = externalId;
        this.views = views;
        this.rates = rates;
        this.follows = follows;
    }

    public User(Long userId) {
        this.id = userId;
    }

    public List<Role> getRoleDetails() {
        return this.roles.stream()
                .map(role -> new Role(role.getId(), role.getName()))
                .collect(Collectors.toList());
    }


    public User(String accountName, String fullName, String password, String email, String image, String idOther, Date createAt, Integer type) {

    }
}
