package com.animeweb.dto.oauth;


import com.animeweb.entities.Permission;
import lombok.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor

public class RoleDTO {
    private Long id ;
    private String name;
    private String description;
    private List<Permission> permissions = new ArrayList<>();
    private Map<Long,String> userMap = new HashMap<>();
}
