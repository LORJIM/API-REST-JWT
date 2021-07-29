package com.exodus.core.config;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import com.fasterxml.jackson.core.JsonProcessingException;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
@Configuration
public class ResourceServerConfig {

	
	
	//Metodo para validar el token que nos envia el cliente en cada peticion
	static Authentication getAuthentication(HttpServletRequest request) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		//Obtenemos el token que viene en el header de la peticion
		String token= request.getHeader("Authorization");
		//Si hay algun token presente, entonces lo validamos
		if(token!=null) {
			try {
				String user=Jwts.parser().setSigningKey(getSigningKey()) //le pasamos la publicKey que teniamos guardada en las properties
						.parseClaimsJws(token.replace("Bearer", "")) //este metodo es el que valida, le hacemos un replace para quitar el bearer y dejar solo el token
						.getBody().getSubject();
				
				//Las peticiones que vienen con token no se validan a traves del authManager porque NO necesitan comparar el user y la password con BBDD,
				//sino que se limitan a validar el token. Por esa razon no es necesario pasar ningun parametro adicional al UsernamePasswordAuthenticationToken de abajo,
				//salvo el usuario sobre el que se ha realizado la validacion
				return user!=null ? new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList()) : null ;
			} catch (SignatureException | ExpiredJwtException e) { //este try catch es necesario para que no pete el java cuando expire el token o cuando no sea valido
				return null;
			}
		}
		return null; //si no hay token, no validamos y pasaremos un null, que se traducira en authentication=false y en el JwtFilter nos dira que nanai
	}
	
	
	//obtiene los factores que componen la publicKey de las properties, y los transforma en dicha publicKey
	private static PublicKey getSigningKey() throws JsonProcessingException, IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		KeyDispatcher keyDispatcher=new KeyDispatcher(); //tenemos que crearlo asi porque un bean inyectado no lo podemos meter en un metodo estatico
		String publicKeyFactors=keyDispatcher.getPublicKey(); //obtenemos modulo y exp (publicKey) de las properties
		String[] factores=publicKeyFactors.replace('"',' ').trim().split("/"); //le quitamos las comillas, los espacios y los separamos
		BigInteger modulus=new BigInteger(factores[0]); //convertimos ambos a BigIntegers
		BigInteger exponent=new BigInteger(factores[1]);
		RSAPublicKeySpec spec=new RSAPublicKeySpec(modulus,exponent);
		  KeyFactory factory=KeyFactory.getInstance("RSA");
		  PublicKey publicKey=factory.generatePublic(spec); //generamos la publicKey correspondiente al modulo y exp guardados
		  return publicKey; //la retornamos
	}
}