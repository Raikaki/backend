package com.animeweb.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Table(name="expired_Token")
public class ExpiredToken {
    @Id
    @Column(name = "id")
    private String id;
    @Column(name="expiryDate", columnDefinition = "datetime")
    Date expiryDate;
}
