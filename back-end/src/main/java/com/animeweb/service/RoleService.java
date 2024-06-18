package com.animeweb.service;

import com.animeweb.dto.oauth.PermissionDTO;
import com.animeweb.dto.oauth.RoleDTO;
import com.animeweb.dto.user.UserDTO;
import com.animeweb.entities.Role;

import java.util.List;

public interface RoleService {
    RoleDTO createRole(RoleDTO roleDTO);
    List<RoleDTO> getAllRole();
    Role findRoleById(Long roleId);
    RoleDTO findRoleDetailById(Long roleId);
    boolean deteleUserRole(Long roleId, Long userId);
    void save(Role role);
    List<PermissionDTO> getEnablePermission(Long roleId);
    PermissionDTO findPermissionById(Long permissionId);
    boolean deleteRolePermission(Long roleId, Long permissionId);
    boolean addRolePermission(Long roleId, Long permissionId);
    boolean findContainsName(Long roleId, String name);
    boolean findContainsName(String name);
    List<UserDTO> findUserNotHaveRole(Long roleId);
    boolean addUserRole(Long roleId, Long userId);
    List<Role> findUserRole(Long id);
}
