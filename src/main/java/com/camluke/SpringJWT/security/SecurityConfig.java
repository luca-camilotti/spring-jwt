package com.camluke.SpringJWT.security;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.json.JSONObject;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.camluke.SpringJWT.filter.CustomAuthenticationFilter;
import com.camluke.SpringJWT.filter.CustomAuthorizationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

@Configuration 
@EnableWebSecurity
@EnableGlobalMethodSecurity(
		securedEnabled = true, // enables @Secured annotation
		jsr250Enabled = true,  // enables @RolesAllowed annotation
		prePostEnabled = true  //  enables @PreAuthorize, @PostAuthorize, @PreFilter, @PostFilter annotations
		)

@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	private final UserDetailsService userDetailsService;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
		customAuthenticationFilter.setFilterProcessesUrl("/api/login");  // Override default /login url

		http.cors();  // Use @CrossOrigin annotation in the API, or a CorsFilter bean
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.authorizeRequests().antMatchers("/api/login/**", "/api/token/refresh/**").permitAll();  // anybody can do login (put url that don't need permission like this before authorized url)
		// Use these instead of @RolesAllowed annotation:
		//http.authorizeRequests().antMatchers("GET", "/api/user/**").hasAnyAuthority("ROLE_USER");
		//http.authorizeRequests().antMatchers("POST", "/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");

		http.authorizeRequests().anyRequest().authenticated();  // authenticated users only
		// http.authorizeRequests().anyRequest().permitAll(); // don't use any security
		// http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));
		http.addFilter(customAuthenticationFilter);
		http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

		http.exceptionHandling()  // handles Unauthenticated Requests: answers 401 Unauthorized
		.authenticationEntryPoint((request, response, e) -> 
		{
			/*
			response.sendError(
					HttpServletResponse.SC_UNAUTHORIZED,
					e.getMessage()
					); */

			// Map<String, String> error = new HashMap<>();
			// error.put("error_message", e.getMessage());
			// new ObjectMapper().writeValue(response.getOutputStream(), error);

			// Handcrafted JSON:
			
	    	JSONObject error = new JSONObject();
			error.put("timestamp", LocalDateTime.now().toString());
			error.put("status", HttpStatus.UNAUTHORIZED.value());
            error.put("message", "Access denied");
            error.put("error", "Unauthorized");
            error.put("path", request.getServletPath());
			// tokens.put("refresh_token", refresh_token);
			response.setStatus(HttpStatus.UNAUTHORIZED.value());
			response.setHeader("error", e.getMessage());
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);			
			response.getWriter().write(error.toString());
			

		});
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}




}
