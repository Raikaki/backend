package com.animeweb.mapper;

import com.animeweb.dto.oauth.RoleDTO;
import com.animeweb.entities.Role;
import com.animeweb.entities.User;

import java.util.HashMap;
import java.util.Map;

public class RoleMapper {
    public static RoleDTO mapToDTO(Role role){
        RoleDTO roleDTO = new RoleDTO();
        roleDTO.setId(role.getId());
        roleDTO.setName(role.getName());
        roleDTO.setDescription(role.getDescription());
        roleDTO.setPermissions(role.getPermissions());
        Map<Long,String> userMap = new HashMap<>();
        for(User user : role.getUsers()){
            userMap.put(user.getId(),user.getUserName());
        }
        roleDTO.setUserMap(userMap);
        return roleDTO;
    }
}
