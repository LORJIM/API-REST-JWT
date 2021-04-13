package com.exodus.core.services;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.exodus.core.dao.UsuarioDAO;
import com.exodus.core.entities.Usuario;

@Service
public class UsuarioService implements UserDetailsService{
	@Autowired
	private UsuarioDAO usuarioDAO;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Usuario user=usuarioDAO.findByUsuario(username);
		//ES IMPORTANTE QUE EN LA COLUMNA ACTIVO EL USUARIO TENGA UN 1, SI TIENE UN 0 EL AUTHMANAGER LO INTERPRETARA COMO BLOQUEADO Y NO LO AUTENTICARA
		return new User(user.getUsuario(), user.getPassword(), user.isActivo(),user.isActivo(),user.isActivo(),user.isActivo(), buildGranted(user.getRole()));
	}
	
	public List<GrantedAuthority> buildGranted(byte rol){ //SEGUN EL NUMERO DE ROL QUE TENGA EN BBDD SE LE ASIGNA UN AUTHORITY U OTRO
		String[] roles= {"LECTOR","USUARIO","ADMINISTRADOR"}; //UN ROL 0 SERIA LECTOR, 1 USUARIO, 2 ADMINISTRADOR....
		List<GrantedAuthority> auths= new ArrayList<>();
		for(int i=0; i<=rol; i++) {
			auths.add(new SimpleGrantedAuthority(roles[i]));
		}
		return auths;
	}
	
}
