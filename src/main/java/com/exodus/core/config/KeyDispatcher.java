package com.exodus.core.config;

import java.io.File;
import java.io.IOException;

import javax.servlet.GenericServlet;
import javax.servlet.ServletContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

@Configuration
public class KeyDispatcher { //sirve para guardar y obtener la publicKey de nuestro YAML de manera dinamica (con @Value solo obtiene el valor que hay al iniciar el server)
	
	private String DeployIndicator=System.getProperty("deployment"); //indicador de que se trata de una ejecucion en un servidor JBOSS (esta propiedad la he puesto en el standalone)
	
	
	public void setPublicKey(String publicKey) throws JsonProcessingException, IOException {
		if(DeployIndicator!=null) {//SI NOS ENCONTRAMOS EN UN SERVIDOR JBOSS, LA PUBLIC KEY la sacamos y actualizamos del standalone.xml
			System.out.println("VIEJA "+System.getProperty("publicKey").toString());
			System.setProperty("publicKey",publicKey);
			System.out.println("NUEVA "+System.getProperty("publicKey").toString());
		}else if(System.getProperty("deployment")==null){
			// Create an ObjectMapper mapper for YAML
			ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
			// Parse the YAML file
			ObjectNode root = (ObjectNode) mapper.readTree(new File("src/main/resources/application.yml")); //en local (tomcat embebido) guardamos la publicKey en el yml
			System.out.println("VIEJA "+root.get("publicKey").toString());
			// Guarda la publicKey (modulo y exp)
			root.put("publicKey", publicKey);
						
			System.out.println("NUEVA "+root.get("publicKey").toString());
						
			// Write changes to the YAML file
			mapper.writer().writeValue(new File("src/main/resources/application.yml"), root);
		}
	}

	public String getPublicKey() throws JsonProcessingException, IOException {
		String publicKey="";
		if(DeployIndicator!=null) { //server JBOSS
			publicKey=System.getProperty("publicKey").toString(); //retorna la publicKey (modulo y exp) del standalone.xml
		}else if(DeployIndicator==null) { //tomcat embebido
			// Create an ObjectMapper mapper for YAML
			ObjectMapper mapper = new ObjectMapper(new YAMLFactory());

			// Parse the YAML file
			ObjectNode root = (ObjectNode) mapper.readTree(new File("src/main/resources/application.yml"));

			publicKey=root.get("publicKey").toString(); //retorna la publicKey (modulo y exp) del YAML
		}
		return publicKey;
	}
	
	
}
