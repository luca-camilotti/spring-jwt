package com.camluke.SpringJWT.models;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity  // This class represents a JPA entity
@Data	// Creates getters and setters automatically
@NoArgsConstructor  // Generates constructor with no arguments
@AllArgsConstructor // Generates constructor with all arguments
public class Role {
	
	@Id  // The id attribute will be the primary key
	@GeneratedValue(strategy = GenerationType.AUTO)
	private Long id; 
	private String name;

}
