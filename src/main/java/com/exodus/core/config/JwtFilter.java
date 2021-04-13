package com.exodus.core.config;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

public class JwtFilter extends GenericFilterBean {
	/*
	 * Las peticiones que no sean /login pasaran por este filtro, 
	 * el cual se encarga de pasar la request a la clase JwtUtil para que valide el token*/

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		Authentication authentication=JwtUtil.getAuthentication((HttpServletRequest)request); //le pasamos la request al jwtutil para que valide el token (autenticacion)
		SecurityContextHolder.getContext().setAuthentication(authentication); //seteamos el resultado de la autenticacion en el contexto de la aplicacion
		chain.doFilter(request, response); //hacemos el filtro, si la autenticacion fallo (tiene valor false), pues el filtro nos dira que nanai
	}
}
