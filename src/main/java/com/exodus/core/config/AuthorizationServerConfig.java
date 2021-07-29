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
import java.util.Arrays;
import java.util.UUID;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.GlobalAuthenticationConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import com.exodus.core.services.ClientService;
import com.exodus.core.services.InstalacionService;
import com.exodus.core.services.UsuarioService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.google.common.collect.ImmutableList;
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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

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
	
	@Autowired
	private Environment env;
	
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
		http.cors().and() //cors() carga la configuracion de mas abajo
		.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).and() //ESTO PARA ENVIAR EL CSRF EN EL XSRF TOKEN (Response Cookie) y utilizar este en vez de JSESSIONID
		//SI NUESTRA APP ES PRIVADA (NO SE ACCEDE POR BUSCADOR), ENTONCES PODEMOS PRESCINDIR DE CSRF Y DESHABILITARLO
        .authorizeRequests(authorizeRequests ->
			authorizeRequests.antMatchers(resources).permitAll() //permitimos el acceso a ciertos recursos (como login y swagger) a cualquiera
			.anyRequest().authenticated() //cualquier otra peticion-endpoint requiere autenticacion
			.and()
			//Adicionalmente, las peticiones a la API pasaran por este filtro, que valida el Access Token
			.addFilterBefore(new JwtFilter(), UsernamePasswordAuthenticationFilter.class)
		)
        .formLogin().defaultSuccessUrl("/login"); //redireccion despues de login con exito, tenemos que especificar algun GET que exista porque sino devolvera error al front aunque el login haya ido bien
		//ya que el POST login y el redireccionamiento GET son interpretados como 1 sola peticion por el front (Axios-Vue)
		//.loginPage("/loginCustom"); aqui estableceriamos la pagina/endpoint de login en caso de querer alguna custom en vez de la default
		return http.build();
	}
	
	
	//CONFIGURACION PARA EVITAR ERRORES DE CORS
		 @Bean
		    public WebMvcConfigurer corsConfigurer() {
		        return new WebMvcConfigurer() {
		            @Override
		            public void addCorsMappings(CorsRegistry registry) {
		                registry.addMapping("/**")
		                        .allowedMethods("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS");
		            }
		        };
		    }

		 @Bean
		    public CorsConfigurationSource corsConfigurationSource() {
		        final CorsConfiguration configuration = new CorsConfiguration();
		        configuration.setAllowedOriginPatterns(Arrays.asList("*"));
		        configuration.setAllowedMethods(ImmutableList.of("HEAD",
		                "GET", "POST", "PUT", "DELETE", "PATCH"));
		        // setAllowCredentials(true) is important, otherwise:
		        // The value of the 'Access-Control-Allow-Origin' header in the response must not be the wildcard '*' when the request's credentials mode is 'include'.
		        configuration.setAllowCredentials(true);
		        // setAllowedHeaders is important! Without it, OPTIONS preflight request
		        // will fail with 403 Invalid CORS request
		        configuration.setAllowedHeaders(ImmutableList.of("Authorization", "Cache-Control", "Content-Type"));
		        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		        source.registerCorsConfiguration("/**", configuration);
		        return source;
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
		ps=ps.issuer(env.getProperty("serverUrl")); //el issuer es la ip-puerto que utilizara para los endpoints
		//si desplegamos en jboss, cogera la del profile de production
		//los profiles son configuraciones para entornos especificos, que sobreescriben las propiedades del yaml
//		 o de entornos previos, segun el orden que ponemos en active profiles del yaml principal
//		 en el resto de yamls definiremos las properties de profiles
		
		//si quisieramos cambiar los endpoints por defecto de oauth, seria a traves del ProviderSettings
		//ps= ps.jwkSetEndpoint("/keys"); //por ejemplo el que sirve para obtener las JWKs
		
		return ps;
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource() throws InvalidKeySpecException, NoSuchAlgorithmException, JsonProcessingException, IOException{ //es un manager de las RSAKeys (pares de keys) que se utilizan para encriptar y validar los JWT
		RSAKey rsaKey=getKeyPair();
		JWKSet jwkSet=new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet); //para obtener las JWKs (publicKeys) -> GET /oauth2/jwks (endpoint por defecto)
	}
	
	
	
}
