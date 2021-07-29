package com.exodus.core.config;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;


public class JwtFilter extends GenericFilterBean {
	
	
	
	/*
	 * Este filtro se encarga de pasar la request al ResourceServer para que valide el access token*/
	private final Log log= LogFactory.getLog(getClass()); //el "objeto" log para esta clase
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String path = ((HttpServletRequest) request).getServletPath();
	    if (path.contains("products")) { //si la peticion es hacia algun endpoint de la API
			Authentication authentication;
			try {
				authentication = ResourceServerConfig.getAuthentication((HttpServletRequest)request); //pasa la request al ResourceServer para que valide el access token (autenticacion)
				if(authentication==null) { //para las excepciones de access token invalido o expirado, en vez de hacer el filtro debemos devolver un 401 Unauthorized especificamente, para que el front sepa que tiene que refrescar
					HttpServletResponse response2=(HttpServletResponse) response;
				    response2.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
				}else {
					SecurityContextHolder.getContext().setAuthentication(authentication); //seteamos el resultado de la autenticacion en el contexto de la aplicacion
					chain.doFilter(request, response); //hacemos el filtro, si la autenticacion fallo (tiene valor false), pues el filtro nos dira que nanai
				}
			} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
	    }else { //de lo contrario solo comprueba que el usuario este autenticado
	    	chain.doFilter(request, response);
	    	return;
			 
	    }
		
	}
}