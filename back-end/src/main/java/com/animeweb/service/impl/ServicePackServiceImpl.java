package com.animeweb.service.impl;

import com.animeweb.dto.payment.ServicePackAdmin;
import com.animeweb.dto.payment.ServicePackDTO;
import com.animeweb.entities.ServicePack;
import com.animeweb.mapper.ServicePackMapper;
import com.animeweb.repository.ServicePackRepository;

import com.animeweb.dto.payment.DashboardView;
import com.animeweb.service.ServicePackService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@Service
public class ServicePackServiceImpl implements ServicePackService {
    @Autowired
    private ServicePackRepository servicePackRepository;
    @Autowired
    CloudinaryService uploadService;
    @Autowired
    UserPackedCustomRepositoryImpl userPackedCustomRepository;

    @Override
    public List<ServicePackDTO> getListServicePack() {
        List<ServicePack> servicePacks = servicePackRepository.findAllByStatusIsTrue();
        List<ServicePackDTO> servicePackDTOS = new ArrayList<>();
        for (ServicePack servicePack : servicePacks) {
            ServicePackDTO servicePackDTO = ServicePackMapper.MaptoDto(servicePack);
            servicePackDTO.setService_img(servicePack.getService_img());
            servicePackDTOS.add(servicePackDTO);
        }
        return servicePackDTOS;
    }

    @Override
    public ServicePackDTO getById(long id) {
        ServicePack servicePack = servicePackRepository.findServicePackById(id);
        return ServicePackMapper.MaptoDto(servicePack);
    }

    @Override
    public void save(ServicePack servicePack) {
            servicePackRepository.save(servicePack);
    }

    @Override
    public ServicePackAdmin createServicePack(ServicePack servicePack) {
        ServicePack pack =   servicePackRepository.save(servicePack);
        return ServicePackMapper.Maptoadmin(pack);
    }

    @Override
    public void updateServicePack(Long id) throws Exception {
            Date now = new Date();
        ServicePack pack =    servicePackRepository.findServicePackById(id);
        uploadService.deleteFolderMovie(uploadService.getServiceFolderById(pack.getId()));
        if(pack!= null){
            pack.setDeleteAt(now);
            pack.setStatus(false);
            servicePackRepository.save(pack);
        }

    }

    @Override
    public boolean existType(String serviceType) {
        return servicePackRepository.existByType(serviceType);
    }

    @Override
    public    List<DashboardView> getUserPackedBoughtMostByMonth() {
        return userPackedCustomRepository.getUserPackedBoughtMostByMonth();
    }

    @Override
    public    List<DashboardView> getUserPackedBoughtMostByYear() {
        return userPackedCustomRepository.getUserPackedBoughtMostByYear();
    }



}
