package com.exodus.core.config;

import org.springframework.context.annotation.Configuration;

@Configuration
public class SecretDispatcher{
	
	//los metodos de creacion y validacion de tokens (JwtUtil) son estaticos, por eso requieren de secrets estaticas y esto nos impide recogerlas
	//de las properties de la aplicacion. Para tenerlas parametrizadas, utilizamos este dispatcher
	public static String secretPrincipal="UmVzdF9BUEk6c2VjcmV0XzEyMzQ=";
	
	
}
