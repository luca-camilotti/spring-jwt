package com.camluke.SpringJWT.service;

import java.util.List;

import com.camluke.SpringJWT.models.AppUser;
import com.camluke.SpringJWT.models.Role;

public interface UserService {
	AppUser saveUser(AppUser user);
	Role saveRole(Role role);
	void addRoleToUser(String username, String rolename);  // assuming the username is unique
	AppUser getUser(String username);
	List<AppUser> getUsers();
}
