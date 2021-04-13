package com.exodus.core.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

public class LoginFilter extends AbstractAuthenticationProcessingFilter{
	//constructor del filtro, le pasamos la url-endpoint al que se lo va aplicar y el authManager, que servira para hacer la autenticacion
	public LoginFilter(String url, AuthenticationManager authManager) {
		super(new AntPathRequestMatcher(url));
		setAuthenticationManager(authManager);
	}

	//metodo que se encarga de recoger la info que le viene de /login y autenticarla a traves del authManager
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		InputStream body=request.getInputStream(); //obtenemos la info de la peticion de login
		User user=new ObjectMapper().readValue(body, User.class); //mapeamos dicha info en un objeto de tipo User
		return getAuthenticationManager().authenticate( //el authenticationManager comparara(autenticara) en BBDD haciendo uso del UsuarioService el objeto que le pasamos abajo
					new UsernamePasswordAuthenticationToken(user.getUser(), user.getPassword(),Collections.emptyList())
				);
		
	}

	//si la autenticacion ha ido bien, se lanza este metodo
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		//creamos y agregamos el token a la respuesta
		JwtUtil.addAuthentication(response, authResult.getName());
	}
	
	
	
}
