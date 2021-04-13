package com.exodus.core.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.exodus.core.dao.UsuarioDAO;
import com.exodus.core.entities.Usuario;

@Service
public class InstalacionService {
	@Autowired
	private UsuarioDAO usuarioDAO;
	
	
	@Autowired
	private Environment env;
	
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	public void init_usuarios() {
		Usuario usuario=usuarioDAO.findByUsuario("lorjim"); //buscamos el usuario por defecto
		if(usuario==null) { //si no existe lo crea-inserta en bbdd
			usuario= new Usuario("lorjim", 
					passwordEncoder.encode("1234"));

			usuarioDAO.save(usuario);
		}
		
	}
}
