package com.exodus.core.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.exodus.core.services.UsuarioService;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter{
	
	@Autowired
	private UsuarioService usuarioService;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	String[] resources= new String[] { //carpetas-recursos especificos a los que damos permiso a cualquiera
			"/include/**","/css/**","/icons/**","/img/**","/js/**","/vendor/**","/login",
			// -- swagger ui
            "/swagger-resources/**",
            "/swagger-ui.html",
            "/v2/api-docs",
            "/webjars/**"
		};
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(usuarioService).passwordEncoder(passwordEncoder());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests() //deshabilitamos el token csrf por defecto de java
		.antMatchers(resources).permitAll() //permitimos el acceso a ciertos recursos (como login y swagger) a cualquiera
		.anyRequest().authenticated() //cualquier otra peticion-endpoint requiere autenticacion
		.and()
		//Las peticiones /login pasaran previamente por este filtro, antes y despues de ser autenticadas
		.addFilterBefore(new LoginFilter("/login", authenticationManager()), UsernamePasswordAuthenticationFilter.class)
		//Las demas peticiones pasaran por este filtro para validar el token
		.addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class);
	}
	
}
