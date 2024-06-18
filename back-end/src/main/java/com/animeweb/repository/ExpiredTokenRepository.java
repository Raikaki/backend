package com.animeweb.repository;

import com.animeweb.entities.ExpiredToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ExpiredTokenRepository extends JpaRepository<ExpiredToken,String> {
}
