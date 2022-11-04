package com.camluke.SpringJWT.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
		
		http.csrf().disable();
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.authorizeRequests().antMatchers("/api/login/**").permitAll();  // anybody can do login (put url that don't need permission like this before authorized url)
		// Use these instead of @RolesAllowed annotation:
		//http.authorizeRequests().antMatchers("GET", "/api/user/**").hasAnyAuthority("ROLE_USER");
		//http.authorizeRequests().antMatchers("POST", "/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");
		
		http.authorizeRequests().anyRequest().authenticated();  // authenticated users only
		// http.authorizeRequests().anyRequest().permitAll(); // don't use any security
		// http.addFilter(new CustomAuthenticationFilter(authenticationManagerBean()));
		http.addFilter(customAuthenticationFilter);
		http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	


}
