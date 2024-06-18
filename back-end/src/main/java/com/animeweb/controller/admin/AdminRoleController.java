package com.animeweb.controller.admin;

import com.animeweb.dto.oauth.PermissionDTO;
import com.animeweb.dto.oauth.RoleDTO;
import com.animeweb.dto.oauth.RoleRequest;
import com.animeweb.dto.user.UserDTO;
import com.animeweb.entities.Role;
import com.animeweb.entities.User;
import com.animeweb.mapper.RoleMapper;
import com.animeweb.service.RoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/admin/roles")
public class AdminRoleController {
    @Autowired
    RoleService roleService;
    @GetMapping()
    @PreAuthorize("hasAuthority('view_roles') or hasRole('ADMIN')")
    public ResponseEntity<List<RoleDTO>> getAllRole(){
        return new ResponseEntity<>(roleService.getAllRole(), HttpStatus.OK);
    }
    @GetMapping("/{roleId}")
    @PreAuthorize("hasAuthority('view_roles') or hasRole('ADMIN')")
    public ResponseEntity<RoleDTO> getRoleById(@PathVariable Long roleId){
        RoleDTO role = roleService.findRoleDetailById(roleId);
        if(role==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Role không tồn tại!");
        return new ResponseEntity<>(role,HttpStatus.OK);
    }
    @GetMapping("/{roleId}/not")
    @PreAuthorize("hasAuthority('view_roles') or hasRole('ADMIN')")
    public ResponseEntity<List<UserDTO>> findUserNotHaveRole(@PathVariable Long roleId){
        RoleDTO role = roleService.findRoleDetailById(roleId);
        if(role==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Role không tồn tại!");
        List<UserDTO> userDTOS = roleService.findUserNotHaveRole(roleId);
        return new ResponseEntity<>(userDTOS,HttpStatus.OK);
    }
    @PostMapping("/{roleId}/user/{userId}")
    @PreAuthorize("hasAuthority('edit_user_roles') or hasRole('ADMIN')")
    public ResponseEntity<String> addRoleUser(@PathVariable Long roleId,@PathVariable Long userId){
        Role role = roleService.findRoleById(roleId);
        if(role==null)  throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Role không tồn tại!");
        if(roleService.addUserRole(roleId,userId)) {
            return new ResponseEntity<>("Đã thêm role " + roleId + " cho user " + userId + " thành công!", HttpStatus.CREATED);
        }else{
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Role này không tồn tại hoặc user không tồn tại!");
        }
    }
    @GetMapping("/{roleId}/permissions")
    @PreAuthorize("hasAuthority('view_roles') or hasRole('ADMIN')")
    public ResponseEntity<List<PermissionDTO>> getEnablePermission(@PathVariable Long roleId){
        if(roleService.findRoleDetailById(roleId)==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Role không tồn tại!");
        List<PermissionDTO> permissionDTOS = roleService.getEnablePermission(roleId);
        return new ResponseEntity<>(permissionDTOS,HttpStatus.OK);
    }
    @PutMapping("/{roleId}/{permissionId}")
    @PreAuthorize("hasAuthority('edit_role') or hasRole('ADMIN')")
    public ResponseEntity<String> addRolePermission(@PathVariable Long roleId, @PathVariable Long permissionId){
        if(roleService.findRoleDetailById(roleId)==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Role không tồn tại!");
        if(roleService.findPermissionById(permissionId)==null)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Quyền hạn không tồn tại!");
        if(roleService.addRolePermission(roleId,permissionId)){
            return new ResponseEntity<>("Đã thêm thành công",HttpStatus.CREATED);
        }else{
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Thêm thất bại, có vẻ như Role hoặc quyền hạn không tồn tại!");
        }
    }
    @PutMapping("/{roleId}")
    @PreAuthorize("hasAuthority('edit_role') or hasRole('ADMIN')")
    public ResponseEntity<String> editRole(@PathVariable Long roleId,@RequestBody RoleRequest roleRequest){
        String roleName = roleRequest.getName();
        if (roleName != null) {
            roleName = roleName.replaceAll("\\s+", "");
        }
        if(roleService.findRoleDetailById(roleId)==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Role không tồn tại!");
        if(roleService.findContainsName(roleId,roleName)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Tên Role đã tồn tại!");
        Role role = roleService.findRoleById(roleId);
        role.setName(roleName);
        role.setDescription(roleRequest.getDescription());
        roleService.save(role);
        return new ResponseEntity<>("Chỉnh sửa thành công!",HttpStatus.CREATED);
    }
    @PostMapping()
    @PreAuthorize("hasAuthority('add_role') or hasRole('ADMIN')")
    public ResponseEntity<RoleDTO> addRole(@RequestBody RoleRequest roleRequest){
        String roleName = roleRequest.getName();
        if (roleName != null) {
            roleName = roleName.replaceAll("\\s+", "");
        }
        if(roleService.findContainsName(roleName)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Tên Role đã tồn tại!");
        Role role = new Role();
        role.setName(roleName);
        role.setDescription(role.getDescription());
        roleService.save(role);

        return new ResponseEntity<>(RoleMapper.mapToDTO(role),HttpStatus.CREATED);
    }
    @DeleteMapping("/{roleId}/{permissionId}")
    @PreAuthorize("hasAuthority('edit_role') or hasRole('ADMIN')")
    public ResponseEntity<String> deleteRolePermission(@PathVariable Long roleId, @PathVariable Long permissionId){
        if(roleService.findRoleDetailById(roleId)==null) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Role không tồn tại!");
        if(roleService.findPermissionById(permissionId)==null)throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Quyền hạn không tồn tại!");
        if(roleService.deleteRolePermission(roleId,permissionId)){
            return new ResponseEntity<>("Đã xóa thành công",HttpStatus.CREATED);
        }else{
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Không tìm thấy quyền hạn tương ứng trong Role!");
        }
    }

    @DeleteMapping("/delete/userRole/{roleId}/{userId}")
    @PreAuthorize("hasAuthority('edit_user_roles') or hasRole('ADMIN')")
    public ResponseEntity<String> deleteUserRole(@PathVariable Long roleId,@PathVariable Long userId){
            if(roleService.deteleUserRole(roleId,userId)) {
                return new ResponseEntity<>("Đã xóa role " + roleId + " cho user " + userId + " thành công!", HttpStatus.CREATED);
            }else{
                throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Role của user này không tồn tại!");
            }
    }
    @DeleteMapping("/delete/{roleId}")
    @PreAuthorize("hasAuthority('delete_role') or hasRole('ADMIN')")
    public ResponseEntity<String> deleteRole(@PathVariable Long roleId){
            Role role = roleService.findRoleById(roleId);
            if(role==null)  throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Role không tồn tại!");
            role.setStatus(false);
            roleService.save(role);
            return new ResponseEntity<>("Đã xóa role "+roleId+" thành công!",HttpStatus.CREATED);
    }}
