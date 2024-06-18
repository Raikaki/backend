package com.animeweb.repository;

import com.animeweb.dto.user.UserDTO;
import com.animeweb.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Repository

public interface UserRepository extends JpaRepository<User,Long> {
    @Query("SELECT a from User a where a.userName=:userName and a.status = true and a.authenticated = true and a.userType=1" )
    Optional<User> findByUserName(String userName);

    @Query("SELECT a from User a where a.id= :id and a.status = true ")
    User findUserByid(Long id);

    @Query("select count(a) > 0 from User a where a.userName=:userName and a.status=true and  a.authenticated = true")
    Boolean existsByUserName(String userName);

    @Query("SELECT a from User a where a.email= :email and a.userType = 2 and  a.status  = true ")
    User findByEmailGoogle(String email);

    @Query("SELECT a from User a where a.email = :email and a.userType = 3 and  a.status  = true ")
    User findByEmailFacebook(String email);

    @Query("select count(a) > 0 from User a where a.email = :email and a.status=true and  a.authenticated = true")
    Boolean existByEmail(String email);

    @Modifying
    @Transactional
    @Query("update User a set a.authenticated = true where a.userName = :userName and a.email = :email and a.authCode = :verifyCode and a.status=true and a.authenticated = false and a.expiredAt > CURRENT_TIMESTAMP")
    Integer updateUserVerificationStatus(String userName, String email, Integer verifyCode);

//    @Query("SELECT a from User a where  a.status  = true and a.id= :id ")
//    Optional<User> findById(Long id);

    @Query("update User a set a.status=false where a.id= :id")
    User deleteUserById(Long id);

    @Query("SELECT a from User a where a.status = true ")
    List<User> findAllUser();

    Boolean existsByEmail(String email);
    User findByEmailAndUserTypeAndStatus(String email, int userType, boolean status);

    @Query("select u from User u where u.isActive=false and u.status=true")
    List<User> GetAllUserLocked();
    User findByIdAndStatusTrue(Long id);
    @Query(value = "select * from users u where authenticated=true and status=true and (u.id in (select distinct user_id from user_roles where role_id!=1 and role_id != :roleId) or u.id not in (select distinct user_id from user_roles))", nativeQuery = true)
    List<User> findUserNotHaveRole(Long roleId);

}


