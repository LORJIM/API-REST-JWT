package com.exodus.core.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import com.nimbusds.jose.jwk.RSAKey.Builder;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig{ 
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}
	/*
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}*/
	
//	este bean es necesario para evitar conflicto con la autoconfig por defecto de Spring Security, es como hacer un override
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
		http.authorizeRequests(authorizeRequests ->
			authorizeRequests.anyRequest().authenticated()
		).formLogin();
		
		return http.build();
	}
	
	@Bean
	public UserDetailsService userDetailsService(){ //devuelve un userdetailsservice que compara con la simulacion de un usuario de BBDD, "bill", esto es por pruebas
		InMemoryUserDetailsManager uds= new InMemoryUserDetailsManager();
		UserDetails u1= User.withUsername("bill").password("12345")
				.authorities("read")
				.build();
		
		uds.createUser(u1);
		
		return uds;
	}
	
	
	@Bean
	public RegisteredClientRepository registeredClientRepository() { //devuelve un clientdetailservice basicamente, un manager de clientes, sus caracteristicas y su validacion en BBDD
		RegisteredClient c1=RegisteredClient.withId("client") //creamos la simulacion de un cliente devuelto por bbdd, con las caracteristicas de debajo
				.clientId("client1").clientSecret("secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC) //hay varios metodos, BASIC es el mas usado, POST como que lleva la info en el mensaje de la peticion post
				
				//habilitamos diferentes grant types para este cliente
				//el AUTHORIZATION CODE se obtiene a traves de un login (cliente previamente autorizado con /oauth2/authorize mandando response_type=code y client_id), 
				//que si es con exito nos redirige a /authorized
				//con el grant_type AUTHORIZATION CODE podemos obtener el ACCESS TOKEN y el REFRESH TOKEN a traves de /oauth2/token
				//esto ultimo deberia hacerse de manera automatica en /authorized, y devolverle los 2 token al cliente
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost:8080/authorized")
				
				//con el grant_type PASSWORD podemos obtener el ACCESS TOKEN y el REFRESH TOKEN a traves de /oauth2/token sin cliente previamente autorizado,
				//directamente con un login con exito y mandando un token Basic con la secret del cliente (igual que en el Portal de Confirming)
				//.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				
				//el REFRESH TOKEN se obtiene a traves del AUTHORIZATION CODE de arriba
				//con el grant_type REFRESH TOKEN podemos obtener un nuevo ACCESS TOKEN y un nuevo REFRESH TOKEN
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				
				//estas token settings son comunes para toda la configuracion
				.tokenSettings(t -> {
					//para que no nos deje utilizar el refresh token mas de una vez, ponemos esto
					t.reuseRefreshTokens(false); //basicamente es para limitar que consigamos access tokens infinitos, esto da seguridad
					
					//para ponerle un tiempo de expiracion al access token
					t.accessTokenTimeToLive(Duration.ofHours(2)); //2 horas de validez
				})
				.scope("read")
				.build();
				
				
		return new InMemoryRegisteredClientRepository(c1);
	}
	
	
	private KeyPair generateKeyPair() { //genera un par de keys tipo RSA, POR DEFECTO SOLO LO HACE CADA VEZ QUE SE REINICIA EL SERVIDOR
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator= KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair=keyPairGenerator.generateKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
		return keyPair;
	}
	
	private RSAKey getKeyPair() {
		KeyPair keyPair= generateKeyPair();
		RSAPublicKey publicKey=(RSAPublicKey) keyPair.getPublic(); //esta key es la que se utiliza para validar los JWT
		RSAPrivateKey privateKey=(RSAPrivateKey) keyPair.getPrivate(); //esta key es la que se utiliza para encriptar los JWT
		return new Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build(); //crea y devuelve una RSAKey conformada por la public y la private anteriores
	}
	
	@Bean
	public ProviderSettings providerSettings() {
		ProviderSettings ps= new ProviderSettings();
		ps=ps.issuer("http://localhost:8080");
		
		//si quisieramos cambiar el endpoint por defecto para obtener la JWK
		//ps= ps.jwkSetEndpoint("/keys");
		
		return ps;
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource(){ //es un manager de las RSAKeys (pares de keys) que se utilizan para encriptar y validar los JWT
		RSAKey rsaKey=getKeyPair();
		JWKSet jwkSet=new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet); //para obtener la JWK -> GET /oauth2/jwks (endpoint por defecto)
	}
	
	
	
}
