package com.camluke.SpringJWT;

import java.util.ArrayList;
import java.util.Arrays;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import com.camluke.SpringJWT.models.AppUser;
import com.camluke.SpringJWT.models.Role;
import com.camluke.SpringJWT.service.UserService;

@SpringBootApplication
public class SpringJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	public CorsFilter corsFilter() {
	    CorsConfiguration corsConfiguration = new CorsConfiguration();
	    corsConfiguration.setAllowCredentials(true);
	    corsConfiguration.setAllowedOrigins(Arrays.asList("http://localhost:4200", "http://localhost:80"));
	    corsConfiguration.setAllowedHeaders(Arrays.asList("Origin", "Access-Control-Allow-Origin", "Content-Type",
	    		"Accept", "Authorization", "Origin, Accept", "X-Requested-With",
	    		"Access-Control-Request-Method", "Access-Control-Request-Headers"));
	    corsConfiguration.setExposedHeaders(Arrays.asList("Origin", "Content-Type", "Accept", "Authorization",
	    		"Access-Control-Allow-Origin", "Access-Control-Allow-Origin", "Access-Control-Allow-Credentials"));
	    corsConfiguration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
	    UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
	    urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
	    return new CorsFilter(urlBasedCorsConfigurationSource);
	}



	@Bean
	CommandLineRunner run(UserService userService) {
		return args -> {
			// adding some roles to database
			userService.saveRole(new Role(null, "ROLE_USER")); // no need to pass the role id, JPA will manage it automatically
			userService.saveRole(new Role(null, "ROLE_MANAGER")); // no need to pass the role id, JPA will manage it automatically
			userService.saveRole(new Role(null, "ROLE_ADMIN")); // no need to pass the role id, JPA will manage it automatically
			userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN")); // no need to pass the role id, JPA will manage it automatically
			userService.saveRole(new Role(null, "ROLE_GUEST")); // no need to pass the role id, JPA will manage it automatically

			// adding some users to database
			userService.saveUser(new AppUser(null, "Chuck Norris", "chuck", "pippo1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Jim Carry", "jim", "pluto1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Bruce Willis", "bruce", "foo1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Arnold Schwarzenegger", "arnold", "buuu1234", new ArrayList<>()));
			userService.saveUser(new AppUser(null, "Steven Seagal", "steve", "mah1234", new ArrayList<>()));

			// adding roles to users
			userService.addRoleToUser("chuck", "ROLE_USER");
			userService.addRoleToUser("chuck", "ROLE_ADMIN");
			userService.addRoleToUser("chuck", "ROLE_SUPER_ADMIN");
			userService.addRoleToUser("jim", "ROLE_GUEST");
			userService.addRoleToUser("bruce", "ROLE_USER");
			userService.addRoleToUser("bruce", "ROLE_ADMIN");
			userService.addRoleToUser("arnold", "ROLE_USER");
			userService.addRoleToUser("arnold", "ROLE_MANAGER");
			userService.addRoleToUser("arnold", "ROLE_ADMIN");
			userService.addRoleToUser("steve", "ROLE_USER");
		};
	}

}
