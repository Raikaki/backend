package com.animeweb.dto.payment;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DashboardView
 {
     private Long ID;
     private String service_type;
     private Double price;
     private Long amount;
 }
