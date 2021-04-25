package com.exodus.core.config;

import java.io.File;
import java.io.IOException;

import org.springframework.context.annotation.Configuration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

@Configuration
public class KeyDispatcher { //sirve para guardar y obtener la publicKey de nuestro YAML de manera dinamica (con @Value solo obtiene el valor que hay al iniciar el server)
	
	public void setPublicKey(String publicKey) throws JsonProcessingException, IOException {
		// Create an ObjectMapper mapper for YAML
		ObjectMapper mapper = new ObjectMapper(new YAMLFactory());

		// Parse the YAML file
		ObjectNode root = (ObjectNode) mapper.readTree(new File("src/main/resources/application.yml"));

		// Guarda la publicKey (modulo y exp)
		root.put("publicKey", publicKey);

		// Write changes to the YAML file
		mapper.writer().writeValue(new File("src/main/resources/application.yml"), root);
	}

	public String getPublicKey() throws JsonProcessingException, IOException {
		// Create an ObjectMapper mapper for YAML
				ObjectMapper mapper = new ObjectMapper(new YAMLFactory());

				// Parse the YAML file
				ObjectNode root = (ObjectNode) mapper.readTree(new File("src/main/resources/application.yml"));

		return root.get("publicKey").toString(); //retorna la publicKey (modulo y exp) del YAML
	}
	
	
}
