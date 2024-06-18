package com.animeweb.service.impl;

import com.animeweb.dto.payment.DashboardView;
import com.animeweb.repository.UserPackedCustomRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;

@Repository
public class UserPackedCustomRepositoryImpl implements UserPackedCustomRepository {

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public List<DashboardView> getUserPackedBoughtMostByMonth() {
        String sql = "SELECT sp.id AS id, sp.service_type AS serviceType, sp.price AS price, COUNT(up.service_pack_id) AS amount " +
                "FROM users_packed up " +
                "JOIN service_packs sp ON up.service_pack_id = sp.id " +
                "WHERE up.create_at >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 MONTH) AND sp.status = 1 " +
                "GROUP BY sp.id, sp.service_type, sp.price " +
                "ORDER BY COUNT(up.service_pack_id) DESC " +
                "LIMIT 2";

        List<Object[]> results = entityManager.createNativeQuery(sql).getResultList();
        List<DashboardView> dashboardViews = new ArrayList<>();

        for (Object[] result : results) {
            DashboardView dashboardView = new DashboardView(
                    ((Number) result[0]).longValue(),
                    (String) result[1],
                    ((Number) result[2]).doubleValue(),
                    ((Number) result[3]).longValue()
            );
            dashboardViews.add(dashboardView);
        }

        return dashboardViews;
    }

    @Override
    public List<DashboardView> getUserPackedBoughtMostByYear() {
        String sql = "SELECT sp.id AS id, sp.service_type AS serviceType, sp.price AS price, COUNT(up.service_pack_id) AS amount " +
                "FROM users_packed up " +
                "JOIN service_packs sp ON up.service_pack_id = sp.id " +
                "WHERE up.create_at >= DATE_SUB(CURRENT_DATE(), INTERVAL 1 YEAR) AND sp.status = 1 " +
                "GROUP BY sp.id, sp.service_type, sp.price " +
                "ORDER BY COUNT(up.service_pack_id) DESC " +
                "LIMIT 2";

        List<Object[]> results = entityManager.createNativeQuery(sql).getResultList();
        List<DashboardView> dashboardViews = new ArrayList<>();

        for (Object[] result : results) {
            DashboardView dashboardView = new DashboardView(
                    ((Number) result[0]).longValue(),
                    (String) result[1],
                    ((Number) result[2]).doubleValue(),
                    ((Number) result[3]).longValue()
            );
            dashboardViews.add(dashboardView);
        }

        return dashboardViews;
    }
}
