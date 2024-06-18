package com.animeweb.dto.payment;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PaymentRequestDTO {
    private long id;
    private Double amount;
    private String currency;
    private String method;
    private String intent;
    private String description;
     private long idUser;
     private long serviceId;

}
