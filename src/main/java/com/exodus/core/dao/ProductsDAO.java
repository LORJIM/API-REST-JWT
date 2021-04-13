package com.exodus.core.dao;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import com.exodus.core.entities.Product;

public interface ProductsDAO extends JpaRepository<Product, Long>{
	public abstract Page<Product> findAll(Pageable pageable); //identico al metodo findall pero con paginacion activada
}
