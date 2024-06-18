package com.animeweb.mapper;

import com.animeweb.dto.oauth.PermissionDTO;
import com.animeweb.entities.Permission;

public class PermissionMapper {
    public static PermissionDTO mapToDTO(Permission permission){
        return new PermissionDTO(permission.getId(),permission.getName(),permission.getDescription());
    }
}
