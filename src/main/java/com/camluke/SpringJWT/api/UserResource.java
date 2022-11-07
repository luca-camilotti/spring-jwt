package com.camluke.SpringJWT.api;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.annotation.security.RolesAllowed;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.camluke.SpringJWT.filter.CustomAuthorizationFilter;
import com.camluke.SpringJWT.models.AppUser;
import com.camluke.SpringJWT.models.Role;
import com.camluke.SpringJWT.service.UserService;
import com.camluke.SpringJWT.utils.AppUtils;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserResource {
	private final UserService userService;
	
	@RolesAllowed({"ROLE_ADMIN", "ROLE_USER"})
	@GetMapping("/users")
	public ResponseEntity<List<AppUser>> getUsers() {
		return ResponseEntity.ok().body(userService.getUsers());
	}
	
	@RolesAllowed("ROLE_ADMIN")
	@PostMapping("/user/save")
	public ResponseEntity<AppUser> saveUser(@RequestBody AppUser user) {
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveUser(user));
	}
	
	@RolesAllowed({"ROLE_ADMIN", "ROLE_SUPER_ADMIN"})
	@PostMapping("/role/save")
	public ResponseEntity<Role> saveRole(@RequestBody Role role) {
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveRole(role));
	}
	
	@PostMapping("/role/addtouser")
	public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form) {
		userService.addRoleToUser(form.getUsername(), form.getRoleName());
		return ResponseEntity.ok().build();  // use build() in case you don't return anything
	}	
	
	// Refresh token api:
	@PostMapping("/token/refresh")
	public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
		String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
		if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
			try {
				String refresh_token = authorizationHeader.substring("Bearer ".length());
				Algorithm algorithm = Algorithm.HMAC256(AppUtils.secret.getBytes());
				JWTVerifier verifier = JWT.require(algorithm).build();
				DecodedJWT decodedJWT = verifier.verify(refresh_token);
				String username = decodedJWT.getSubject();  // Get username from token
				AppUser user =userService.getUser(username); // Verify the username exists in the database
				// Create a new fresh tokens:
				String access_token = JWT.create()
						.withSubject(user.getUsername())
						.withExpiresAt(new Date(System.currentTimeMillis() +AppUtils.tokenDurationMs))
						.withIssuer(request.getRequestURL().toString())
						.withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
						.sign(algorithm);				
				// Send tokens in the response body (JSON format):
				Map<String, String> tokens = new HashMap<>();
				tokens.put("access_token", access_token);
				tokens.put("refresh_token", refresh_token);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				new ObjectMapper().writeValue(response.getOutputStream(), tokens);
				
			}
			catch(Exception e) {
				log.error("Login error: {}", e.getMessage());
				response.setHeader("error", e.getMessage());
				
				// Classic body:
				// response.sendError(HttpStatus.FORBIDDEN.value());
				
				// Error in the body in JSON format:
				Map<String, String> error = new HashMap<>();
				error.put("error_message", e.getMessage());
				// tokens.put("refresh_token", refresh_token);
				response.setStatus(HttpStatus.FORBIDDEN.value());
				response.setHeader("error", e.getMessage());
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				try {
					new ObjectMapper().writeValue(response.getOutputStream(), error);
				} catch (IOException e1) {
					throw new RuntimeException(e1.getMessage());					
				}
			}
		}
		else
			throw new RuntimeException("Refresh token is missing");
	}
	
}

@Data
class RoleToUserForm {
	private String username;
	private String roleName;
}
