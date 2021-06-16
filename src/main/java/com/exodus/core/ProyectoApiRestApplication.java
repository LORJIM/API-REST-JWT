package com.exodus.core;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;


//import com.exodus.core.services.InstalacionService;

@SpringBootApplication
public class ProyectoApiRestApplication extends SpringBootServletInitializer implements CommandLineRunner{

//	@Autowired
//	private InstalacionService instalacionService;
	
	@Override //Este metodo es del servlet initializer y es necesario para poder exportar el proyecto a JAR o WAR
    public SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application.sources(ProyectoApiRestApplication.class);
    }
    
	public static void main(String[] args) {
		SpringApplication.run(ProyectoApiRestApplication.class, args);
	}

	
	@Override
	public void run(String... args) throws Exception {
//		instalacionService.init_usuarios(); //crea usuario por defecto en caso de que no lo haya-exista en bbdd
		//proximamente crear uno por defecto para cliente tambien
	}
	
}
