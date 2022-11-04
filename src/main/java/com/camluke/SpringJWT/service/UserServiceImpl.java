package com.camluke.SpringJWT.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.camluke.SpringJWT.models.AppUser;
import com.camluke.SpringJWT.models.Role;
import com.camluke.SpringJWT.repo.AppUserRepo;
import com.camluke.SpringJWT.repo.RoleRepo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor  // for dependency injection
@Transactional  // to modify database changing entity objects
@Slf4j // log
public class UserServiceImpl implements UserService, UserDetailsService {

	private final AppUserRepo userRepo;
	private final RoleRepo roleRepo;
	private final PasswordEncoder passwordEncoder; // to encode password
	
	@Override
	public AppUser saveUser(AppUser user) {
		log.info("Saving new user {} to database", user.getName());
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userRepo.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		log.info("Saving new role {} to database", role.getName());
		return roleRepo.save(role);
	}

	@Override
	public void addRoleToUser(String username, String rolename) {
		log.info("Adding role {} to user {}", rolename, username);
		// Transactional operation: use the entity objects to modify the database
		AppUser user = userRepo.findByUsername(username);
		Role role = roleRepo.findByName(rolename);
		user.getRoles().add(role);
		
	}

	@Override
	public AppUser getUser(String username) {
		log.info("Fetching user {}", username);
		return userRepo.findByUsername(username);
	}

	@Override
	public List<AppUser> getUsers() {
		log.info("Fetching all user ");
		return userRepo.findAll();
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser user = userRepo.findByUsername(username);
		if(user == null) {
			log.error("User {} not found in database", username);
			throw new UsernameNotFoundException("User "+username+" not found in database");
		}
		else
			log.info("User {} found in database", username);
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		user.getRoles().forEach(role -> {  // create the authorities list
			authorities.add(new SimpleGrantedAuthority(role.getName()));
		});
		return new User(user.getUsername(), user.getPassword(), authorities);
	}

}
