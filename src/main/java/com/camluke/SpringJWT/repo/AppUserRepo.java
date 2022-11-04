package com.camluke.SpringJWT.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.camluke.SpringJWT.models.AppUser;

public interface AppUserRepo extends JpaRepository<AppUser, Long>{

	AppUser findByUsername(String username);
}
