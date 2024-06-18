package com.animeweb.repository;

import com.animeweb.entities.Role;
import com.animeweb.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role,Long> {
   Role findByNameAndStatusTrue(String name);
   @Query("select r from Role r where r.status = true and r.name !='ADMIN'")
   List<Role> getAllRole();
   @Query("SELECT u FROM Role r JOIN r.users u WHERE r.id = :roleId AND u.status = true AND u.authenticated = true")
   List<User> findUsersByRole(Long roleId);
   @Modifying
   @Transactional
   @Query(value = "delete from user_roles where user_id = :userId and role_id = :roleId", nativeQuery = true)
   int removeUserRole(Long roleId, Long userId);
   Role findByIdAndStatusTrue(Long id);
   @Modifying
   @Transactional
   @Query(value ="delete from roles_permissions where role_id = :roleId and permissions_id = :permissionId" ,nativeQuery = true)
   int removeRolePermission(Long roleId, Long permissionId);
   @Modifying
   @Transactional
   @Query(value ="insert into roles_permissions values(:roleId,:permissionId)" ,nativeQuery = true)
   int addRolePermission(Long roleId, Long permissionId);
   @Modifying
   @Transactional
   @Query(value ="insert into user_roles values(:userId,:roleId)" ,nativeQuery = true)
   int addUserRole(Long roleId, Long userId);
   Boolean existsRoleByNameAndAndStatusTrueAndIdIsNot(String name,Long id);
   Boolean existsRoleByNameAndAndStatusTrue(String name);

   @Query(value = "select * from roles where id in (select role_id from user_roles where user_id=:id) and status=true",nativeQuery = true)
    List<Role> findByUserId(Long id);
}
