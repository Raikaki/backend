package com.animeweb.entities;

import jakarta.persistence.*;
import lombok.*;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "service_packs")
public class ServicePack {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private Long id;
    @Column(name = "service_type")
    private String service_type;
    @Column(name = "service_img")
    private String service_img;
    @Column(name="price")
    private Double price;
    @Column(name = "create_at",columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    private Date createAt = new Date();

    @Column(name = "update_at", columnDefinition = "datetime")
    private Date updateAt;

    @Column(name = "delete_at", columnDefinition = "datetime")
    private Date deleteAt;

    @Column(name = "status",columnDefinition = "tinyint default 1")
    private Boolean status = true;

    public ServicePack(Long id, String service_type, Double price, Date createAt) {
        this.id = id;
        this.service_type = service_type;
        this.price = price;
        this.createAt = createAt;
    }
}
