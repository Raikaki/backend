package com.animeweb.controller.admin;

import com.animeweb.dto.payment.DashboardView;
import com.animeweb.dto.payment.ServicePackDTO;
import com.animeweb.dto.user.UserDTO;
import com.animeweb.service.UserPackedService;
import com.animeweb.service.impl.ServicePackServiceImpl;
import com.animeweb.service.impl.UserPackedServiceImpl;
import com.paypal.orders.Money;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.util.List;

@RequestMapping("/admin/userservice")
@RestController
@RequiredArgsConstructor

public class UserServicePackController {
    private final UserPackedService userPackedService;
    private final ServicePackServiceImpl servicePackService;
    @GetMapping("/month/{month}")
    @PreAuthorize("hasAuthority('view_revenue') or hasRole('ADMIN')")
    public ResponseEntity<Long> GetRevenueByMonth(@PathVariable Long month) {

        return ResponseEntity.ok(userPackedService.GetRevenueByMonth(month));
    }
    @GetMapping("/revenue")
    @PreAuthorize("hasAuthority('view_revenue') or hasRole('ADMIN')")
    public ResponseEntity<Long> GetRevenueByMonth() {
        return ResponseEntity.ok(userPackedService.getRevenue());
    }
    @GetMapping("/hot/month")
    @PreAuthorize("hasAuthority('view_services') or hasRole('ADMIN')")
    public ResponseEntity<List<DashboardView>> getUserPackedBoughtMostByMonth() {
        return ResponseEntity.ok(servicePackService.getUserPackedBoughtMostByMonth());
    }

    @GetMapping("/hot/year")
    @PreAuthorize("hasAuthority('view_services') or hasRole('ADMIN')")

    public ResponseEntity<List<DashboardView>> getUserPackedBoughtMostByYear() {
        return ResponseEntity.ok(servicePackService.getUserPackedBoughtMostByYear());
    }
    @GetMapping("/all/user/bought")
    @PreAuthorize("hasAuthority('view_services') or hasRole('ADMIN')")

    public ResponseEntity<List<UserDTO>> GetAllUserBought() {
        return ResponseEntity.ok(userPackedService.GetAllUserBought());
    }
    @GetMapping
    @PreAuthorize("hasAuthority('view_services') or hasRole('ADMIN')")

    public ResponseEntity<List<ServicePackDTO>> getServiceList() {
        return ResponseEntity.ok(servicePackService.getListServicePack());
    }

}
