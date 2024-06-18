package com.animeweb.service.impl;

import com.animeweb.entities.Role;
import com.animeweb.entities.User;
import com.animeweb.exception.EmailAlreadyExistException;
import com.animeweb.exception.UserNotFoundException;
import com.animeweb.exception.UsernameAlreadyExistException;
import com.animeweb.repository.RoleRepository;
import com.animeweb.repository.UserRepository;
import com.animeweb.request.CreateUserRequest;
import com.animeweb.request.UpdateUserRequest;
import com.animeweb.service.AdminService;
import com.animeweb.service.RoleService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AdminServiceImpl implements AdminService {

    private final UserRepository userRepository;
    private final RoleService roleService;
    private final RoleRepository roleRepository;
    private final CloudinaryService uploadService;
    private final UserServiceImpl userService;

    /**
     * Delete user by id<br/>
     * <strong>This method will delete the user completely, consider when using this method</strong>
     *
     * @param id user id
     */
    @Override
    public void deleteUser(Long id) {
        Optional<User> user = userRepository.findById(id);
        if (user.isEmpty())
            throw new UserNotFoundException("User with the id does not exist");
        else {
            var newUser = user.get();
            newUser.setStatus(false);
            userRepository.save(newUser);
            log.info("Delete user successfully: {}", newUser.getId());

        }

    }

    @Override
    public void updateUser(Long id, UpdateUserRequest request) throws IOException {
        Optional<User> user = userRepository.findById(id);
        if (user.isEmpty())
            throw new RuntimeException("User with the id does not exist");
        else {
            var newUser = user.get();
            newUser.setPhone(request.phone() != null ? request.phone() : newUser.getPhone());
            newUser.setFullName(request.name() != null ? request.name() : newUser.getFullName());
            newUser.setEmail(request.email() != null ? request.email() : newUser.getEmail());
            newUser.setUpdatedAt(new Date());
            PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);

            newUser.setPassword(request.password() != null ? passwordEncoder.encode(request.password()) : newUser.getPassword());

            if (request.avatarPicture() != null) {
                String avatar = uploadService.uploadUserAvt(request.avatarPicture(), newUser.getId());
                newUser.setAvatarPicture(avatar);
            }
            userRepository.save(newUser);

            log.info("Update user successfully: {}", newUser.getId());
        }
    }


    @Override
    public void createUser(CreateUserRequest request) throws IOException {
        log.info("status: {}", userRepository.existsByUserName(request.username()));

        isAccountValid(request.username(), request.email());
        User user = new User();
        user.setUserName(request.username());

        user.setFullName(request.name());
        user.setPhone(request.phone());
        user.setEmail(request.email());
        user.setAuthenticated(true);
        user.setStatus(true);
        user.setRoles(List.of(roleRepository.findByNameAndStatusTrue("USER")));
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
        user.setPassword(passwordEncoder.encode(request.password()));
        String avatar = uploadService.uploadUserAvt(request.avatarPicture(), user.getId());
        user.setAvatarPicture(avatar);
        userRepository.save(user);

        log.info("Insert user successfully: {}", user.getId());
    }


    @Override
    public void deactivateUser(Long id) {
        Optional<User> user = userRepository.findById(id);
        if (user.isEmpty())
            throw new UserNotFoundException("User with the id does not exist");
        else {
            var newUser = user.get();
            newUser.setIsActive(!newUser.getIsActive());
            userRepository.save(newUser);
            log.info("Deactivate user successfully: {}", newUser.getId());
        }
    }

    @Override
    public void setRole(Long id, Long roleId) {
        Optional<User> user = userRepository.findById(id);
        if (user.isEmpty())
            throw new UserNotFoundException("User with the id does not exist");
        else {
            var newUser = user.get();
            var role = roleService.findRoleById(roleId);

            Role userRole = new Role();
            userRole.setId(role.getId());
            userRole.setName(role.getName());
            newUser.setRoles(List.of(userRole));

            userRepository.save(newUser);
            log.info("Set role for user successfully: {}", newUser.getId());
        }
    }

    @Override
    public List<User> getAllUser() {
        return userRepository.findAllUser();
    }

    @Override
    public User changPassword(String oldPassword, String newPassword, String passwordConfirm, Long id) {
        Optional<User> user = userRepository.findById(id);
        PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);
        User existingUser=null;
        if (user.isPresent()) {
            existingUser = user.get();
            boolean isMatch = newPassword.equals(passwordConfirm);
            if (passwordEncoder.matches(oldPassword, existingUser.getPassword()) && isMatch) {
                existingUser.setPassword(passwordEncoder.encode(newPassword));
                userRepository.save(existingUser);
            }
        }
        return existingUser;
    }

    @Override
    public List<User> GetAllUserLocked() {
        return userRepository.GetAllUserLocked();
    }


    private void isAccountValid(String username, String email) {
        if (userRepository.existsByUserName(username)) {
            throw new UsernameAlreadyExistException("Username already exists");
        }

        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistException("Email already exists");
        }
    }
}
