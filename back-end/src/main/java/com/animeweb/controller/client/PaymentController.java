package com.animeweb.controller.client;

import com.animeweb.dto.payment.PaymentRequestDTO;
import com.animeweb.dto.payment.ServicePackDTO;
import com.animeweb.dto.payment.UserPackedDTO;
import com.animeweb.entities.ServicePack;
import com.animeweb.entities.User;
import com.animeweb.entities.UserPacked;
import com.animeweb.mapper.ServicePackMapper;
import com.animeweb.mapper.UserPackedMapper;
import com.animeweb.repository.ServicePackRepository;
import com.animeweb.repository.UserPackedRepository;
import com.animeweb.service.UserPackedService;
import com.animeweb.service.impl.PayPalService;
import com.animeweb.service.impl.ServicePackServiceImpl;
import com.animeweb.service.impl.UserPackedServiceImpl;
import com.animeweb.service.impl.UserServiceImpl;
import com.paypal.api.payments.Links;
import com.paypal.api.payments.Payment;
import com.paypal.base.rest.PayPalRESTException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.temporal.TemporalUnit;
import java.util.Calendar;
import java.util.Date;

// PaymentController.java
@RestController
@RequestMapping("/payment")
public class PaymentController {

    @Autowired
    private PayPalService payPalService;
    @Autowired
    private UserServiceImpl userService;
    @Autowired
    private UserPackedServiceImpl userPackedService;
    @Autowired
    private ServicePackServiceImpl servicePackService;

    @PostMapping("/create-payment")
    public ResponseEntity<?> createAndExecutePayment(@RequestBody PaymentRequestDTO request) {
        try {
            Payment payment = payPalService.createPayment(request.getAmount(), request.getCurrency(), request.getMethod(), request.getIntent(), request.getDescription(), "http://localhost:3000/servicePack", "http://localhost:3000/execute-payment");
            String approvalUrl = null;
            for (Links link : payment.getLinks()) {
                if (link.getRel().equalsIgnoreCase("approval_url")) {
                    approvalUrl = link.getHref();
                    break;
                }
            }


            if (approvalUrl != null) {
                System.out.println(request);
                long userId = request.getIdUser();
                long serviceId = request.getServiceId();
                String redirectUrl = approvalUrl ;
                return ResponseEntity.ok(redirectUrl);
            } else {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: approval_url not found");
            }
        } catch (PayPalRESTException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/execute")
    public ResponseEntity<?> executePayment(@RequestParam("paymentId") String paymentId, @RequestParam("payerId") String payerId, @RequestParam("userId") String userId, @RequestParam("serviceId") String serviceId) {
        try {
            Payment payment = payPalService.executePayment(paymentId, payerId);
            String captureId = payment.getTransactions().get(0).getRelatedResources().get(0).getSale().getParentPayment();
            ServicePackDTO servicePack = servicePackService.getById(Long.parseLong(serviceId));
            Date now = new Date();
            Calendar calendar = Calendar.getInstance();
            calendar.setTime(now);

            Date expireTime;
            if (servicePack.getService_type().equals("WEEK")) {
                calendar.add(Calendar.DAY_OF_MONTH, 7);
                expireTime = calendar.getTime();
            } else if (servicePack.getService_type().equals("MONTH")) {
                calendar.add(Calendar.MONTH, 1);
                expireTime = calendar.getTime();
            } else {
                calendar.add(Calendar.YEAR, 1);
                expireTime = calendar.getTime();
            }
            System.out.println(userId);
            System.out.println(serviceId);
            System.out.println(captureId);
            User user = userService.getUserById(userId);
            boolean checkBuyed = userPackedService.checkUserBuyedService(user);
            if(checkBuyed){
                UserPacked userPacked = userPackedService.getUserPacked(user);
                userPacked.setStatus(false);
                userPacked.setExpiredTime(now);
                userPackedService.save(userPacked);
            }
            ServicePackDTO servicePackDTO = servicePackService.getById(Long.parseLong(serviceId));
            ServicePack servicePackEn = ServicePackMapper.MaptoEntiy(servicePackDTO);
            UserPackedDTO userPackedDTO = new UserPackedDTO(user ,servicePackEn, expireTime);
            UserPacked userPacked = UserPackedMapper.mapToEntity(userPackedDTO);
            userPacked.setUserId(user);
            userPacked.setServicePackId(servicePackEn);
            userPacked.setExpiredTime(expireTime);
            userPackedService.save(userPacked);
            return ResponseEntity.ok("success");
        } catch (PayPalRESTException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
