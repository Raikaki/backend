package com.animeweb.controller.admin;

import com.animeweb.entities.User;
import com.animeweb.repository.RoleRepository;
import com.animeweb.request.CreateUserRequest;
import com.animeweb.request.PasswordChangeRequest;
import com.animeweb.request.UpdateUserRequest;
import com.animeweb.security.JwtGenerator;
import com.animeweb.service.AdminService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/admin/user")
@RequiredArgsConstructor
@Slf4j
public class UserManageController {
    private final AdminService adminService;

    @GetMapping
    public List<User> getUsers() {
        return adminService.getAllUser();
    }

    @PostMapping
    public ResponseEntity<User> createUser(@ModelAttribute CreateUserRequest request) throws IOException {
        adminService.createUser(request);
        return ResponseEntity.ok().build();
    }

    @PatchMapping("/{id}")
    public ResponseEntity<User> updateUser(@PathVariable("id") Long id,
                                           @ModelAttribute UpdateUserRequest request) throws IOException {
        adminService.updateUser(id, request);
        return ResponseEntity.ok().build();
    }

    @PatchMapping("/delete/{id}")
    public ResponseEntity<User> delete(@PathVariable Long id) {
        adminService.deleteUser(id);
        return ResponseEntity.ok().build();
    }

    @PatchMapping("/deactivate/{id}")
    public ResponseEntity<User> deactivateUser(@PathVariable Long id) {
        adminService.deactivateUser(id);
        return ResponseEntity.ok().build();
    }

    @PatchMapping("/role/{id}")
    public ResponseEntity<User> setRole(@PathVariable Long id, @RequestBody Long roleId) {
        adminService.setRole(id, roleId);
        return ResponseEntity.ok().build();
    }


}