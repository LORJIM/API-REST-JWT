package com.exodus.core;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

//import com.exodus.core.services.InstalacionService;

@SpringBootApplication
public class ProyectoApiRestApplication implements CommandLineRunner{

	@Autowired
//	private InstalacionService instalacionService;

    
	public static void main(String[] args) {
		SpringApplication.run(ProyectoApiRestApplication.class, args);
	}

	
	@Override
	public void run(String... args) throws Exception {
//		instalacionService.init_usuarios(); //crea usuario por defecto en caso de que no lo haya-exista en bbdd
	}
}
