package com.animeweb.repository;

import com.animeweb.entities.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PermissionRepository extends JpaRepository<Permission,Long> {
    Permission findByName(String name);
    @Query(value = "select * from Permissions p where p.id not in (select permissions_id from roles_permissions where role_id = :roleId)",nativeQuery = true)
    List<Permission> findEnable(Long roleId);
}
