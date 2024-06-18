package com.animeweb.service;

import com.animeweb.dto.user.UserDTO;
import com.animeweb.dto.user.UserServicePackedDTO;
import com.animeweb.entities.User;
import com.animeweb.entities.UserPacked;
import com.paypal.orders.Money;
import org.springframework.data.repository.query.Param;

import java.math.BigDecimal;
import java.util.List;

public interface UserPackedService {
    boolean checkUserBuyedService(User idUser);
    UserPacked getUserPacked(User idUser);

    List<UserPacked>  findAllUserPacked();
    void deleteUserPacked(Long id);
    List<UserServicePackedDTO> getServicePackActiveByUserId(Long userId);
    List<UserServicePackedDTO> getServicePackExpiredByUserId(Long userId);
    List<UserDTO> GetAllUserBought();
    Long GetRevenueByMonth(Long month);
    Long getRevenue();
}
