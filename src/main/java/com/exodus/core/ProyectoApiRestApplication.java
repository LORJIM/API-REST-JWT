package com.exodus.core;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;


@SpringBootApplication
public class ProyectoApiRestApplication extends SpringBootServletInitializer{

	
	@Override //Este metodo es del servlet initializer y es necesario para poder exportar el proyecto a JAR o WAR
    public SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(ProyectoApiRestApplication.class);
    }
    
	public static void main(String[] args) {
		SpringApplication.run(ProyectoApiRestApplication.class, args);
	}
	
}
