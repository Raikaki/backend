package com.animeweb.controller.admin;

import com.animeweb.service.UserPackedService;
import com.paypal.orders.Money;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;

@RequestMapping("/admin/userservice/")
@RestController
@RequiredArgsConstructor

public class UserServicePackController {
    private final UserPackedService userPackedService;

    @GetMapping("/month/{month}")
    public ResponseEntity<Long> GetRevenueByMonth(@PathVariable Long month) {

        return ResponseEntity.ok(userPackedService.GetRevenueByMonth(month));
    }
    @GetMapping("/revenue")
    public ResponseEntity<Long> GetRevenueByMonth() {
        return ResponseEntity.ok(userPackedService.getRevenue());
    }
}
