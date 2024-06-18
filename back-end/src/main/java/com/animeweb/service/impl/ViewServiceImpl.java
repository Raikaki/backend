package com.animeweb.service.impl;

import com.animeweb.entities.Movie;
import com.animeweb.repository.ViewRepository;
import com.animeweb.service.ViewService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
@Service
public class ViewServiceImpl implements ViewService {
    @Autowired
    private ViewRepository viewRepository;
    @Override
    public List<Movie> GetTop5MovieViewedByYear() {
        return viewRepository.getTop5MovieViewedByYear();
    }

    @Override
    public List<Movie> GetTop5MovieViewedByMonth() {
        return viewRepository.getTop5MovieViewedByMonth();
    }
}
