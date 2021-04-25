package com.exodus.core.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.exodus.core.entities.Client;

public interface ClientDAO  extends JpaRepository<Client, Long>{

}
