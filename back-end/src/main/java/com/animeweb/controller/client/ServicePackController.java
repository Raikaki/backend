package com.animeweb.controller.client;

import com.animeweb.dto.payment.DashboardView;
import com.animeweb.dto.payment.ServicePackAdmin;
import com.animeweb.dto.payment.ServicePackDTO;
import com.animeweb.dto.payment.UserPackedDTO;
import com.animeweb.dto.user.UserDTO;
import com.animeweb.dto.user.UserServicePackedDTO;
import com.animeweb.entities.ServicePack;
import com.animeweb.entities.UserPacked;
import com.animeweb.mapper.ServicePackMapper;
import com.animeweb.mapper.UserPackedMapper;
import com.animeweb.service.ServicePackService;
import com.animeweb.service.UserPackedService;
import com.animeweb.service.impl.CloudinaryService;
import com.animeweb.service.impl.ServicePackServiceImpl;
import com.animeweb.service.impl.UserPackedServiceImpl;
import com.animeweb.service.impl.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/servicePack")
public class ServicePackController {
    @Autowired
    private ServicePackServiceImpl servicePackService;
    @Autowired
    private UserPackedServiceImpl userPackedService;
    @Autowired
    private UserPackedService userPackedServices;
    @Autowired
    UserServiceImpl userService;
    @Autowired
    CloudinaryService uploadService;

    @GetMapping
    public ResponseEntity<List<ServicePackDTO>> getServiceList() {
        return ResponseEntity.ok(servicePackService.getListServicePack());
    }
    @GetMapping("/findAll")
    public ResponseEntity<List<UserServicePackedDTO>> getAllServicePackByUserId(@RequestParam Long userID) {
        List<UserServicePackedDTO> list = userPackedServices.getServicePackActiveByUserId(userID);
        if (list.isEmpty()) {
            list = userPackedServices.getServicePackExpiredByUserId(userID);
        }
        return ResponseEntity.ok(list);
    }



}
