package com.exodus.core.dao;

import java.io.Serializable;

import org.springframework.data.jpa.repository.JpaRepository;

import com.exodus.core.entities.Usuario;

public interface UsuarioDAO extends JpaRepository<Usuario, Serializable>{
	public abstract Usuario findByUsuario(String usuario);
}
