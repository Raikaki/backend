package com.animeweb.controller.client;

import com.animeweb.dto.user.UpdateUser;
import com.animeweb.dto.user.UserDTOBuilder;
import com.animeweb.entities.*;
import com.animeweb.repository.UserRepository;
import com.animeweb.request.PasswordChangeRequest;
import com.animeweb.service.AdminService;
import com.animeweb.service.impl.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/account")
public class UserController {
    @Autowired
    private UserServiceImpl userService;

    @Autowired
    private AdminService adminService;

    @GetMapping("/view/{id}")
    public ResponseEntity<UserDTOBuilder> viewProfile(@PathVariable Long id) {
        User user = userService.findUserById(id);
        if(user==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"User không tồn tại");
        List<Long> viewIdList = user.getViews().stream()
                .map(View::getId)
                .collect(Collectors.toList());
        List<Long> rateIDList = user.getRates().stream()
                .map(Rate::getId)
                .collect(Collectors.toList());
        List<Long> followIdList = user.getFollows().stream()
                .map(Follow::getId)
                .collect(Collectors.toList());
        UserDTOBuilder userDTO = new UserDTOBuilder(user.getId(), user.getRoles(), user.getUserName(), user.getAvatarPicture()
                , "", user.getEmail(), user.getFullName(), user.getPhone(), user.getUserType(), user.getCreatedAt(), user.getUpdatedAt()
                , user.getDeletedAt(), user.getStatus(), user.getExternalId(), user.getIsActive(), viewIdList, rateIDList, followIdList);
        return new ResponseEntity<>(userDTO, HttpStatus.OK);
    }

    @PatchMapping("/update")
    public ResponseEntity<User> updateProfile( @ModelAttribute UpdateUser user) throws IOException {
        return ResponseEntity.ok(userService.updateProfile(user));
    }

    @GetMapping("/deActive")
    public ResponseEntity<List<User>> GetAllUserLocked() {
        return ResponseEntity.ok(adminService.GetAllUserLocked());
    }

    @PatchMapping("/changePassword/{id}")
    public ResponseEntity<User> updatePassword(@ModelAttribute PasswordChangeRequest password, @PathVariable Long id) {
        User u = adminService.changPassword(password.oldPassword(), password.newPassword(), password.confirmPassword(), id);
        return ResponseEntity.ok(u);
    }
}