package com.animeweb.repository;


import com.animeweb.entities.User;
import com.animeweb.entities.UserPacked;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
@Repository
public interface UserPackedRepository extends JpaRepository<UserPacked, Long> {
    @Query("select u from UserPacked u where u.userId = :userId and u.status = true")
    UserPacked checkUserBuyedService(User userId);

    @Query("select u from UserPacked u ")
    List<UserPacked> findAllUserPacked();

    @Query("select u from UserPacked u where u.userId = :userId ")
    List<UserPacked> findAllUserPackedByUserId(User userId);

    @Query("select u from ServicePack s join UserPacked u on s.id=u.servicePackId.id where u.status=true and u.userId.id= :userID and u.expiredTime = (SELECT max (u.expiredTime) FROM UserPacked u )")
    List<UserPacked> getAllServicePackBoughtActive(@Param("userID") Long userID);

    @Query("select u from ServicePack s join UserPacked u on s.id=u.servicePackId.id where u.status=false and u.userId.id= :userID and u.expiredTime = (SELECT max (u.expiredTime) FROM UserPacked u )")
    List<UserPacked> getAllServicePackBoughtExpired(@Param("userID") Long userID);
    @Query("select distinct u.userId from UserPacked  u")
    List<User> getAllUserBought();
    @Query("select sum(s.price)from UserPacked  u join ServicePack s on u.servicePackId.id=s.id where year(u.createdAt)=year(current_date) and month(u.createdAt)= :month")
    Long getRevenueByMonth(@Param("month")Long month);
    @Query("select sum(s.price)from UserPacked  u join ServicePack s on u.servicePackId.id=s.id where year(u.createdAt)=year(current_date)")
    Long getRevenue();
}
