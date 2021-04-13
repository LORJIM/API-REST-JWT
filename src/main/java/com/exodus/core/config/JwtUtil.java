package com.exodus.core.config;

import java.util.Collections;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JwtUtil {
	
	// Metodo para crear el JWT y enviarlo al front en el header de la respuesta
	static void addAuthentication(HttpServletResponse res, String username) {
		String token=Jwts.builder().setSubject(username) //CREAMOS EL TOKEN PARA ESTE USUARIO EN CONCRETO
				.setExpiration(new Date(System.currentTimeMillis() + 120000)) //le ponemos un tiempo de expiracion de 2 minutos
				//cuando expire lanzara un error 500 retornado por ExpiredJwtException
				//Hash con el que encriptaremos la clave
				/*
				| If you're signing with: | your key (byte array) length MUST be: |
				| ----------------------- | ------------------------------------- |
				| HMAC SHA 256            | >= 256 bits (32 bytes)                |
				| HMAC SHA 384            | >= 384 bits (48 bytes)                |
				| HMAC SHA 512            | >= 512 bits (64 bytes)                |*/
				.signWith(SignatureAlgorithm.HS512,SecretDispatcher.secretPrincipal) //la encriptacion recoge 2 argumentos, un algoritmo y una secret
				//la secret es una frase a nuestra eleccion, codificada en base64 y que cumpla los requisitos de la tabla de arriba, si no dara un error de que
				//la secret viene empty o null
				.compact(); 
				
		
				//agregamos al header authorization el token
				res.addHeader("Authorization", "Bearer "+token);
				//si quisieramos devolver otros headers globales aparte del token, tambien lo hariamos aqui
	}
	
	//Metodo para validar el token que nos envia el cliente en cada peticion
	static Authentication getAuthentication(HttpServletRequest request) {
		//Obtenemos el token que viene en el header de la peticion
		String token= request.getHeader("Authorization");
		
		//Si hay algun token presente, entonces lo validamos
		if(token!=null) {
			String user=Jwts.parser().setSigningKey(SecretDispatcher.secretPrincipal) //le pasamos la secret, definida arriba en la creacion de tokens
					.parseClaimsJws(token.replace("Bearer", "")) //este metodo es el que valida, le hacemos un replace para quitar el bearer y dejar solo el token
					.getBody().getSubject();
			
			//Las peticiones que vienen con token no se validan a traves del authManager porque NO necesitan comparar el user y la password con BBDD,
			//sino que se limitan a validar el token. Por esa razon no es necesario pasar ningun parametro adicional al UsernamePasswordAuthenticationToken de abajo,
			//salvo el usuario sobre el que se ha realizado la validacion
			return user!=null ? new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList()) : null ;
		}
		return null; //si no hay token, no validamos y pasaremos un null, que se traducira en authentication=false y en el JwtFilter nos dira que nanai
	}
}
