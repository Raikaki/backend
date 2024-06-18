package com.animeweb.service;

import com.animeweb.entities.User;
import com.animeweb.request.CreateUserRequest;
import com.animeweb.request.UpdateUserRequest;

import java.io.IOException;
import java.util.List;

public interface AdminService {

    void createUser(CreateUserRequest request) throws IOException;

    void deleteUser(Long id);

    void updateUser(Long id, UpdateUserRequest request) throws IOException;

    void deactivateUser(Long id);

    void setRole(Long id, Long roleId);

    List<User> getAllUser();

    User changPassword(String oldPassword, String newPassword,String passwordConfirm, Long id);

    List<User> GetAllUserLocked();
}