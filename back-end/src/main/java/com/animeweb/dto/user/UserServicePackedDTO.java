package com.animeweb.dto.user;

import com.animeweb.entities.ServicePack;
import com.animeweb.entities.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserServicePackedDTO {
    private Long id;
    private Long userId;
    private ServicePack servicePackId;
    private Date expiredTime;
    private Date createdAt;
    private Boolean status;
}