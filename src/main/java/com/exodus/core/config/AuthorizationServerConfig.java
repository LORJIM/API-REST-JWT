package com.exodus.core.config;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import com.exodus.core.services.ClientService;
import com.exodus.core.services.InstalacionService;
import com.exodus.core.services.UsuarioService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.RSAKey.Builder;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig  extends GlobalAuthenticationConfigurerAdapter{ //el adaptador es necesario para hacer override al metodo init (userdetailsservice)
	
	private final Log log= LogFactory.getLog(getClass()); //el "objeto" log para esta clase
	
	@Autowired
	private KeyDispatcher keyDispatcher;
	
	@Autowired
	private UsuarioService usuarioService;
	
	@Autowired
	private ClientService clientService;
	
	@Autowired
	private InstalacionService instalacionService;
	
	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
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
	
//	este bean es necesario para evitar conflicto con la autoconfig por defecto de Spring Security, es como hacer un override
	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
		http.authorizeRequests(authorizeRequests ->
			authorizeRequests.antMatchers(resources).permitAll() //permitimos el acceso a ciertos recursos (como login y swagger) a cualquiera
			.anyRequest().authenticated() //cualquier otra peticion-endpoint requiere autenticacion
			.and()
			//Adicionalmente, las peticiones a la API pasaran por este filtro, que valida el Access Token
			.addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class)
		).formLogin(); //aqui estableceriamos la pagina de login en caso de querer alguna custom en vez de la default
		return http.build();
	}
	
	
	/*SIMULACION DE USUARIOS INMEMORY (SOLO PARA TESTING)
	@Bean
	public UserDetailsService userDetailsService(){ //devuelve un userdetailsservice que compara con la simulacion de un usuario de BBDD, "bill", esto es por pruebas
		InMemoryUserDetailsManager uds= new InMemoryUserDetailsManager();
		UserDetails u1= User.withUsername("bill").password("12345")
				.authorities("read")
				.build();
		
		uds.createUser(u1);

		return uds;
	}*/
	
	
	@Override
    public void init(AuthenticationManagerBuilder auth) throws Exception {
		instalacionService.init_usuarios(); //crea usuario por defecto en caso de que no lo haya-exista en bbdd
		instalacionService.init_clientes(); //crea cliente por defecto en caso de que no lo haya-exista en bbdd
		
		//EL USERDETAILSSERVICE SE ENCARGA DE VALIDAR LAS CREDENCIALES DE USUARIO
		//le pasamos el USUARIOSERVICE que se encarga de recuperar los datos del usuario de BBDD (si es que existe)
		//le pasamos tambien el password encoder que debe utilizar para encriptar la password introducida y compararla con la de BBDD
        auth.userDetailsService(usuarioService).passwordEncoder(bCryptPasswordEncoder()); 
    }
	
	@Bean
	public RegisteredClientRepository registeredClientRepository() { //hace el papel de un clientdetailservice basicamente, un manager de clientes, sus caracteristicas y su validacion en BBDD
		//el servicio obtiene los clientes de BBDD y los convierte a RegisteredClients, estos se los pasamos al InMemoryRepository, para que figuren en el contexto de la aplicacion
		return new InMemoryRegisteredClientRepository(clientService.registerClients()); 
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
	
	private RSAKey getKeyPair() throws InvalidKeySpecException, NoSuchAlgorithmException, JsonProcessingException, IOException {
		KeyPair keyPair= generateKeyPair();
		RSAPublicKey publicKey=(RSAPublicKey) keyPair.getPublic(); //esta key es la que se utiliza para validar los JWT
		KeyFactory kf=KeyFactory.getInstance("RSA");
	    RSAPublicKeySpec spec=kf.getKeySpec( publicKey,RSAPublicKeySpec.class);
	    String factores=spec.getModulus()+"/"+spec.getPublicExponent(); //obtenemos los factores que componen la publicKey (modulo y exponente)
	    keyDispatcher.setPublicKey(factores); //la publicKey no se puede guardar directamente, asi que guardamos los numeros que la componen en nuestra property 'publicKey' a traves del keyDispatcher
		RSAPrivateKey privateKey=(RSAPrivateKey) keyPair.getPrivate(); //esta key es la que se utiliza para encriptar los JWT
		return new Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build(); //crea y devuelve una RSAKey conformada por la public y la private anteriores
	}
	
	@Bean
	public ProviderSettings providerSettings() {
		ProviderSettings ps= new ProviderSettings();
		ps=ps.issuer("http://localhost:8080"); //cuando autorizas te redirige a esta url + authorized + codigo de autorizacion
		
		//si quisieramos cambiar el endpoint por defecto para obtener las JWKs
		//ps= ps.jwkSetEndpoint("/keys");
		
		return ps;
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource() throws InvalidKeySpecException, NoSuchAlgorithmException, JsonProcessingException, IOException{ //es un manager de las RSAKeys (pares de keys) que se utilizan para encriptar y validar los JWT
		RSAKey rsaKey=getKeyPair();
		JWKSet jwkSet=new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet); //para obtener las JWKs (publicKeys) -> GET /oauth2/jwks (endpoint por defecto)
	}
	
	
	
}
