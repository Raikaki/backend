package com.animeweb.mapper;

import com.animeweb.dto.payment.ServicePackAdmin;
import com.animeweb.dto.payment.ServicePackDTO;
import com.animeweb.entities.*;


public class ServicePackMapper {
    public static ServicePackDTO MaptoDto(ServicePack servicePack) {
        return new ServicePackDTO(servicePack.getId(), servicePack.getService_type(), servicePack.getPrice(),
                servicePack.getCreateAt());
    }


    public static ServicePack mapToEntity(ServicePackAdmin servicePackAdmin) {
        ServicePack pack = new ServicePack();
        pack.setId(servicePackAdmin.getId());
        pack.setService_type(servicePackAdmin.getService_type());
        pack.setCreateAt(servicePackAdmin.getCreatedAt());
        pack.setPrice(servicePackAdmin.getPrice());
        return pack;
    }

    public static ServicePack MaptoEntiy(ServicePackDTO servicePack) {
        return new ServicePack(servicePack.getId(), servicePack.getService_type(), servicePack.getPrice(), servicePack.getCreatedAt());
    }

    public static ServicePackAdmin Maptoadmin(ServicePack servicePack) {
        ServicePackAdmin pack = new ServicePackAdmin();
        pack.setId(servicePack.getId());
        pack.setService_type(servicePack.getService_type());
        pack.setCreatedAt(servicePack.getCreateAt());
        pack.setPrice(servicePack.getPrice());
        return pack;
    }
}
