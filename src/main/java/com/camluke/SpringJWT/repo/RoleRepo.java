package com.camluke.SpringJWT.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.camluke.SpringJWT.models.Role;

public interface RoleRepo extends JpaRepository<Role, Long>{

	Role findByName(String name);
}
