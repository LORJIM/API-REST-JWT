package com.exodus.core.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import com.exodus.core.dao.ClientDAO;
import com.exodus.core.dao.UsuarioDAO;
import com.exodus.core.entities.Client;
import com.exodus.core.entities.Usuario;

@Service
public class InstalacionService {
	@Autowired
	private UsuarioDAO usuarioDAO;
	
	@Autowired
	private ClientDAO clienteDAO;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	public void init_usuarios() {
		List<Usuario> usuarios=usuarioDAO.findAll(); //buscamos usuarios
		if(usuarios.isEmpty()) { //si no existe ninguno, crea-inserta uno por defecto en bbdd
			Usuario usuario= new Usuario("admin", //usuario
					passwordEncoder.encode("admin"), //password
					(byte)0, //role
					true); //activo

			usuarioDAO.save(usuario);
		}
		
	}
	
	public void init_clientes() {
		List<Client> clientes=clienteDAO.findAll(); //buscamos clientes
		if(clientes.isEmpty()) { //si no existe ninguno, crea-inserta uno por defecto en bbdd
			Client cliente= new Client("client1", //clientId
					"secret1", //clientSecret
					"read", //scope
					"authorization_code,refresh_token", //authorizedGrantTypes
					"ROLE_GENERAL", //authorities
					5, //accessTokenValidity
					false); //reuseRefreshToken

			clienteDAO.save(cliente);
		}
	}
}
