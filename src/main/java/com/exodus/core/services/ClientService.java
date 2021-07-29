package com.exodus.core.services;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;

import com.exodus.core.dao.ClientDAO;
import com.exodus.core.entities.Client;

@Service
public class ClientService{ //convierte la info de los clients de bbdd a registered clients para poderlos meter en inmemory (PROVISIONAL HASTA QUE HAYA CLIENTDETAILSSERVICE)
	@Autowired
	private ClientDAO clientDAO;
	
	@Autowired
	private Environment env;
	
	private List<RegisteredClient> registeredClients=new ArrayList<RegisteredClient>();
	
	public List<RegisteredClient> registerClients(){
		List<Client> clients=clientDAO.findAll(); //recuperamos nuestros clientes en BBDD
		for (Client client : clients) { //convertimos cada Client a RegisteredClient a traves del builder
			RegisteredClient.Builder clientBuilder=RegisteredClient.withId(client.getId().toString()) //el builder recopila las caracteristicas del cliente y cuando tiene todo lo registra (build)
					.clientId(client.getClientId()).clientSecret(client.getClientSecret())
					.clientAuthenticationMethod(ClientAuthenticationMethod.BASIC); //hay varios metodos, BASIC es el mas usado, POST como que lleva la info en el mensaje de la peticion post
			
			
			//habilitamos diferentes grant types para este cliente
			//el AUTHORIZATION CODE se obtiene a traves de /oauth2/authorize mandando response_type=code y client_id (el usuario debe haberse autenticado primero), 
			//que si va con exito nos redirige a /authorized
			//con el grant_type AUTHORIZATION CODE podemos obtener el ACCESS TOKEN y el REFRESH TOKEN a traves de /oauth2/token
			//esto ultimo deberia hacerse de manera automatica en /authorized, y devolverle los 2 token al cliente
			
			//la manera antigua de ponerlo a pelo
//			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost:8080/authorized")
			
			
			//con el grant_type PASSWORD podemos obtener el ACCESS TOKEN y el REFRESH TOKEN a traves de /oauth2/token sin cliente previamente autorizado,
			//directamente con un login con exito y mandando un token Basic con la secret del cliente (igual que en el Portal de Confirming)
			//.authorizationGrantType(AuthorizationGrantType.PASSWORD)
			
			//Para los clientes que sean nuestros (desarrollados por nosotros) utilizamos PASSWORD que es menos seguro pero mas eficiente
			//Para terceros clientes utilizamos AUTHORIZATION CODE que es el mas seguro pero menos eficiente
			
			//el REFRESH TOKEN se obtiene a traves del AUTHORIZATION CODE o a traves de PASSWORD
			//con el grant_type REFRESH TOKEN podemos obtener un nuevo ACCESS TOKEN y un nuevo REFRESH TOKEN
	
			//la manera antigua de ponerlo a pelo
			//.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			
			String[] grantTypes=client.getAuthorizedGrantTypes().split(",");
			for (String grantType : grantTypes) {
				if(grantType.equals("authorization_code")) {
					//de la misma manera que en el login, en el redireccionamiento de authorize hay que poner un GET que exista, para que al front no devuelva error
					//en spring security un get que nos sirve para estas cosas es la del jboss mismo, para no mezclar otros gets que si devuelven info
					//la de serverURL no la utilizo porque con la / al final falla la peticion
					clientBuilder.authorizationGrantType(new AuthorizationGrantType(grantType)).redirectUri(env.getProperty("serverIp"));
				}else {
					clientBuilder.authorizationGrantType(new AuthorizationGrantType(grantType));
				}
			}
					//estas token settings son comunes para toda la configuracion
			RegisteredClient clientBuilded=clientBuilder.tokenSettings(t -> {
						//para que no nos deje utilizar el refresh token mas de una vez, ponemos esto
						t.reuseRefreshTokens(client.isReuseRefreshToken()); //basicamente es para limitar que consigamos access tokens infinitos, esto da seguridad
						
						//para ponerle un tiempo de expiracion al access token
						t.accessTokenTimeToLive(Duration.ofMinutes(client.getAccessTokenValidity())); //5 minutos de validez
					})
					.scope(client.getScope())
					.build(); //finalmente crea el objeto RegisteredClient
			registeredClients.add(clientBuilded); //lo agregamos a la lista de clientes registrados
		}
		
		return registeredClients; //retornamos la lista
	}
}
