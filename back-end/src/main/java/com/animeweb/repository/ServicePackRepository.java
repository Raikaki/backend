package com.animeweb.repository;

import com.animeweb.entities.ServicePack;
import com.animeweb.dto.payment.DashboardView;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface ServicePackRepository extends JpaRepository<ServicePack,Long> {

    List<ServicePack> findAllByStatusIsTrue();
    ServicePack findFirstByStatusNotNullOrderByIdDesc();
    List<ServicePack> findAll();
    @Query("SELECT s FROM ServicePack s WHERE s.id = :id and s.status=true")
    ServicePack findServicePackById(Long id);

    @Query("select count(s)>0 from ServicePack s where s.service_type=:type and s.status=true")
    Boolean existByType(String type);



}