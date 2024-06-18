package com.animeweb.dto.payment;

import com.animeweb.entities.*;

import lombok.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Date;


@Data
@NoArgsConstructor
@AllArgsConstructor
public class ServicePackDTO {
    private Long id;
    private String service_type;
    private Double price;
    private Date createdAt;
    private String service_img;

    public ServicePackDTO(Long id, String serviceType, Double price, Date createAt) {
        this.id = id;
        this.service_type = serviceType;
        this.price = price;
        this.createdAt = createAt;
    }


}
