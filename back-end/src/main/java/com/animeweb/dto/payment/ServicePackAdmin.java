package com.animeweb.dto.payment;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

import java.io.Serializable;
import java.util.Date;
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ServicePackAdmin implements Serializable {
    private Long id;
    private String service_type;
    private Double price;
    private Date createdAt;
    private MultipartFile file;
}
