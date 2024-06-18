package com.animeweb.repository;

import com.animeweb.dto.payment.DashboardView;

import java.util.List;

public interface UserPackedCustomRepository {
    List<DashboardView> getUserPackedBoughtMostByMonth();
    List<DashboardView> getUserPackedBoughtMostByYear();
}
