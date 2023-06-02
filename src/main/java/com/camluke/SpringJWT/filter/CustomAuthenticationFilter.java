package com.camluke.SpringJWT.filter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.camluke.SpringJWT.service.UserService;
import com.camluke.SpringJWT.utils.AppUtils;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	
	
	public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		
	}
	
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		// Manage authentication here
		String username = request.getParameter("username");
		String password = request.getParameter("password");
		log.info("Username: {}, Password: {}", username, password);
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);
		return authenticationManager.authenticate(token);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authentication) throws IOException, ServletException {
		// Create and send access token here:
		User user = (User) authentication.getPrincipal();
		Algorithm algorithm = Algorithm.HMAC256(AppUtils.secret.getBytes());
		String access_token = JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() +AppUtils.tokenDurationMs))
				.withIssuer(request.getRequestURL().toString())
				.withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
				.sign(algorithm);
		
		String refresh_token = JWT.create()
				.withSubject(user.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis() +AppUtils.refreshTokenDurationMs))
				.withIssuer(request.getRequestURL().toString())
				.sign(algorithm);
		
		// Tokens in the header:
		/*
		response.setHeader("access_token", access_token);
		response.setHeader("refresh_token", refresh_token);
		*/
		
		JSONObject tokens = new JSONObject();
		tokens.put("timestamp", LocalDateTime.now().toString());
		tokens.put("status", HttpStatus.OK.value());
		tokens.put("message", "token created");
        //error.put("error", "Unauthorized");
		tokens.put("path", request.getServletPath());
        tokens.put("username", user.getUsername());		
		tokens.put("accessToken", access_token);
		tokens.put("refreshToken", refresh_token);		
		response.setStatus(HttpStatus.OK.value());
		//response.setHeader("error", e.getMessage());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);			
		response.getWriter().write(tokens.toString());
		
		// Send tokens in the response body (JSON format):
		/*
		Map<String, String> tokens = new HashMap<>();
		tokens.put("id", user.getUsername());
		tokens.put("id", user.getAuthorities().toArray());
		tokens.put("accessToken", access_token);
		tokens.put("refreshToken", refresh_token);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		new ObjectMapper().writeValue(response.getOutputStream(), tokens);
		*/
				
	}

}
