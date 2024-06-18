package com.animeweb.service.impl;

import com.animeweb.dto.user.UserDTO;
import com.animeweb.dto.user.UserServicePackedDTO;
import com.animeweb.entities.User;
import com.animeweb.entities.UserPacked;
import com.animeweb.mapper.UserMapper;
import com.animeweb.mapper.UserPackedMapper;
import com.animeweb.repository.UserPackedRepository;
import com.animeweb.repository.UserRepository;
import com.animeweb.service.UserPackedService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Service
public class UserPackedServiceImpl implements UserPackedService {
    @Autowired
    UserPackedRepository userPackedRepository;
    @Autowired
    UserRepository userRepository;

    public void save(UserPacked userPacked) {
        userPackedRepository.save(userPacked);
    }

    @Override
    public boolean checkUserBuyedService(User idUser) {
        UserPacked isBuyed = userPackedRepository.checkUserBuyedService(idUser);
        if (isBuyed == null) {
            return false;
        } else {
            Date now = new Date();
            if (isBuyed.getExpiredTime().compareTo(now) > 0) {
                return true;
            } else {
                return false;
            }
        }
    }

    @Override
    public UserPacked getUserPacked(User idUser) {
        return userPackedRepository.checkUserBuyedService(idUser);
    }

    @Override
    public List<UserPacked> findAllUserPacked() {
        return userPackedRepository.findAllUserPacked();
    }

    public List<UserPacked> findAllUserPackedById(User user) {
        return userPackedRepository.findAllUserPackedByUserId(user);
    }

    @Override
    public void deleteUserPacked(Long id) {
        Date now = new Date();

        UserPacked userPacked = userPackedRepository.findById(id).get();
        userPacked.setStatus(false);
        userPacked.setDeletedAt(now);
        userPacked.setExpiredTime(now);
        userPackedRepository.save(userPacked);
    }

    @Override
    public List<UserServicePackedDTO> getServicePackActiveByUserId(Long userId) {
        List<UserPacked> list = userPackedRepository.getAllServicePackBoughtActive(userId);
        List<UserServicePackedDTO> userPackedDTOList = new ArrayList<>();
        for (UserPacked u : list
        ) {
            userPackedDTOList.add(UserPackedMapper.mapToEntity(u));
        }
        return userPackedDTOList;
    }

    @Override
    public List<UserServicePackedDTO> getServicePackExpiredByUserId(Long userId) {
        List<UserPacked> list = userPackedRepository.getAllServicePackBoughtExpired(userId);
        List<UserServicePackedDTO> userPackedDTOList = new ArrayList<>();
        for (UserPacked u : list
        ) {
            userPackedDTOList.add(UserPackedMapper.mapToEntity(u));
        }
        return userPackedDTOList;
    }

    @Override
    public List<UserDTO> GetAllUserBought() {
        List<User> userList = userPackedRepository.getAllUserBought();
        List<UserDTO> userDTO = new ArrayList<UserDTO>();
        for (User u : userList
        ) {
            userDTO.add(UserMapper.mapToDto(u));
        }
        return userDTO;
    }

    @Override
    public Long GetRevenueByMonth(Long month) {
        return userPackedRepository.getRevenueByMonth(month);
    }

    @Override
    public Long getRevenue() {
        return userPackedRepository.getRevenue();
    }
}
