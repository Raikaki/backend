package com.animeweb.service.impl;

import com.animeweb.dto.oauth.PermissionDTO;
import com.animeweb.dto.oauth.RoleDTO;
import com.animeweb.dto.user.UserDTO;
import com.animeweb.entities.Permission;
import com.animeweb.entities.Role;
import com.animeweb.entities.User;
import com.animeweb.mapper.PermissionMapper;
import com.animeweb.mapper.RoleMapper;
import com.animeweb.mapper.UserMapper;
import com.animeweb.repository.PermissionRepository;
import com.animeweb.repository.RoleRepository;
import com.animeweb.repository.UserRepository;
import com.animeweb.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class RoleServiceImpl implements RoleService {
    @Autowired
    RoleRepository roleRepository;
    @Autowired
    PermissionRepository permissionRepository;
    @Autowired
    UserRepository userRepository;
    @Override
    public RoleDTO createRole(RoleDTO roleDTO) {
        return null;
    }

    @Override
    public List<RoleDTO> getAllRole() {
        List<Role> roles = roleRepository.getAllRole();
        List<Role> roles_users = new ArrayList<>();
        List<User> getUserRoles;
        for(Role role : roles){
            getUserRoles = roleRepository.findUsersByRole(role.getId());
            role.setUsers(getUserRoles);
            roles_users.add(role);
        }
        List<RoleDTO> roleDTOS = new ArrayList<>();
        RoleDTO roleDTO;
        for(Role role : roles_users){
            roleDTO = new RoleDTO();
            roleDTO.setId(role.getId());
            roleDTO.setName(role.getName());
            roleDTO.setDescription(role.getDescription());
            roleDTO.setPermissions(role.getPermissions());
            Map<Long,String> userMap = new HashMap<>();
            for(User user : role.getUsers()){
                userMap.put(user.getId(),user.getUserName());
            }
            roleDTO.setUserMap(userMap);
            roleDTOS.add(roleDTO);
        }

        return roleDTOS;
    }

    @Override
    public RoleDTO findRoleDetailById(Long roleId) {
        Role role = roleRepository.findByIdAndStatusTrue(roleId);
        if(role==null) return null;
        return RoleMapper.mapToDTO(role);
    }

    @Override
    public Role findRoleById(Long roleId) {
        return roleRepository.findByIdAndStatusTrue(roleId);
    }
    @Override
    public boolean deteleUserRole(Long roleId, Long userId) {
        return roleRepository.removeUserRole(roleId,userId) == 1;
    }

    @Override
    public void save(Role role) {
        roleRepository.save(role);
    }

    @Override
    public List<PermissionDTO> getEnablePermission(Long roleId) {
        List<Permission> permissions = permissionRepository.findEnable(roleId);
        List<PermissionDTO> permissionDTOS = new ArrayList<>();
        for(Permission permission : permissions){
            permissionDTOS.add(PermissionMapper.mapToDTO(permission));
        }
        return permissionDTOS;
    }

    @Override
    public PermissionDTO findPermissionById(Long permissionId) {
        Permission permission = permissionRepository.findById(permissionId).orElse(null);
        return permission==null?null:PermissionMapper.mapToDTO(permission);
    }

    @Override
    public boolean deleteRolePermission(Long roleId, Long permissionId) {
        return roleRepository.removeRolePermission(roleId,permissionId)==1;
    }

    @Override
    public boolean addRolePermission(Long roleId, Long permissionId) {
        return roleRepository.addRolePermission(roleId,permissionId)==1;
    }

    @Override
    public boolean findContainsName(Long roleId, String name) {
        return roleRepository.existsRoleByNameAndAndStatusTrueAndIdIsNot(name,roleId);
    }
    @Override
    public boolean findContainsName(String name) {
        return roleRepository.existsRoleByNameAndAndStatusTrue(name);
    }

    @Override
    public List<UserDTO> findUserNotHaveRole(Long roleId) {
        List<User> users = userRepository.findUserNotHaveRole(roleId);
        List<UserDTO> userDTOS = new ArrayList<>();
        for(User user : users){
            userDTOS.add(UserMapper.mapToUserNotRole(user));
        }
        return userDTOS;
    }

    @Override
    public List<Role> findUserRole(Long userId) {
        return roleRepository.findByUserId(userId);
    }
    @Override
    public boolean addUserRole(Long roleId, Long userId) {
        return roleRepository.addUserRole(roleId,userId)==1;
    }



}
