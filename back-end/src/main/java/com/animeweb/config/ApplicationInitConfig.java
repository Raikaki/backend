package com.animeweb.config;

import com.animeweb.entities.Permission;
import com.animeweb.entities.Role;
import com.animeweb.entities.User;
import com.animeweb.enums.InitPermission;
import com.animeweb.repository.PermissionRepository;
import com.animeweb.repository.RoleRepository;
import com.animeweb.repository.UserRepository;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Configuration
public class ApplicationInitConfig {
    @Bean
    ApplicationRunner applicationRunner(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, PermissionRepository permissionRepository) {
        return args -> {
            if (roleRepository.findByNameAndStatusTrue("ADMIN") == null) {
                Role role = new Role();
                role.setName(com.animeweb.enums.Role.ADMIN.name());
                role.setDescription(com.animeweb.enums.Role.ADMIN.name());
                roleRepository.save(role);
            }
            if (roleRepository.findByNameAndStatusTrue("USER") == null) {
                Role role = new Role();
                role.setName(com.animeweb.enums.Role.USER.name());
                role.setDescription(com.animeweb.enums.Role.USER.name());
                roleRepository.save(role);
            }

            if(permissionRepository.findByName("view_dashboard")==null){
                Permission permission = new Permission();
                permission.setName("view_dashboard");
                permission.setDescription("view_dashboard");
                permissionRepository.save(permission);
            }
            Permission viewAdmin = permissionRepository.findByName("view_dashboard");
            for(String roleName : InitPermission.ROLE_PERMISSIONS.keySet()){
                if(roleRepository.findByNameAndStatusTrue(roleName)==null){
                    Role role = new Role();
                    role.setName(roleName);role.setDescription(roleName);
                    List<Permission> rolePermission = new ArrayList<>();
                    Permission permission;
                    for(String permissionName : InitPermission.ROLE_PERMISSIONS.get(roleName)){
                        permission = permissionRepository.findByName(permissionName);
                        if(permission==null){
                            permission = new Permission();
                            permission.setName(permissionName);
                            permission.setDescription(permissionName);
                            permissionRepository.save(permission);
                        }
                        rolePermission.add(permission);
                    }
                    rolePermission.add(viewAdmin);
                    role.setPermissions(rolePermission);
                    roleRepository.save(role);
                }
            }
            if (userRepository.findByUserName(com.animeweb.enums.Role.ADMIN.name()).isEmpty()) {
                User admin = new User();
                admin.setUserName(com.animeweb.enums.Role.ADMIN.name());
                admin.setAvatarPicture("https://s0.smartresize.com/wallpaper/252/68/HD-wallpaper-anime-live-kurumi-tokisaki-art-anime-live-kurumi-tokisaki-art-anime.jpg");
                admin.setPassword(passwordEncoder.encode("123456789"));
                admin.setAuthenticated(true);
                admin.setFullName("ADMIN");
                Role role = roleRepository.findByNameAndStatusTrue("ADMIN");
                userRepository.save(admin);
                admin.setRoles(Collections.singletonList(role));
                userRepository.save(admin);
            }
        };
    }
}
