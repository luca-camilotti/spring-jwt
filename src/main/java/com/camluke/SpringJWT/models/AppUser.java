package com.camluke.SpringJWT.models;

import java.util.ArrayList;
import java.util.Collection;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * User model used in JPA
 * @author luke
 * @version 1.0
 * @since 4/11/2022
 *
 */
@Entity  // This class represents a JPA entity
@Data	// Creates getters and setters automatically
@NoArgsConstructor  // Generates constructor with no arguments
@AllArgsConstructor // Generates constructor with all arguments
public class AppUser {
	@Id  // The id attribute will be the primary key
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id; 
	private String name;
	private String username; // can be the user email
	private String password;
	// ManyToMany relationship: a user may have more roles, a role may be set to more users
	@ManyToMany(fetch = FetchType.EAGER)  // EAGER = load all user roles every time you load a user
	private Collection<Role> roles = new ArrayList<>();

}
