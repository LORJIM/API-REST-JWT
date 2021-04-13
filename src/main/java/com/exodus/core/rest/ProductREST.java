package com.exodus.core.rest;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.exodus.core.dao.ProductsDAO;
import com.exodus.core.dao.UsuarioDAO;
import com.exodus.core.entities.Product;
import com.exodus.core.entities.Usuario;

@RestController
@RequestMapping("/products")
public class ProductREST {
	
	@Autowired
	private ProductsDAO productDAO;
	@Autowired
	private UsuarioDAO usuarioDAO;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@GetMapping
	public ResponseEntity<List<Product>> getProduct(){
		List<Product> products=productDAO.findAll();
		return ResponseEntity.ok(products);
	}
	
	@GetMapping(path="/{productId}")
	public ResponseEntity<Product> getProductById(@PathVariable("productId") Long productId){
		Optional<Product> product=productDAO.findById(productId); //optional nos protege de que la query nos devuelva un valor nulo
		if(product.isPresent()) {
			return ResponseEntity.ok(product.get());
		}else {
			return ResponseEntity.noContent().build();
		}
		
	}
	
	@PostMapping
	public ResponseEntity<Product> createProduct(@RequestBody Product product){
		Product newProduct=productDAO.save(product);
		return ResponseEntity.ok(newProduct);
	}
	
	@PostMapping(path="/addUser")
	public ResponseEntity<Usuario> addUser(@RequestBody Usuario usuario){
		usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
		Usuario newUser=usuarioDAO.save(usuario);
		return ResponseEntity.ok(newUser);
	}
	
	@DeleteMapping(path="/{productId}")
	public ResponseEntity<Void> deleteProduct(@PathVariable("productId") Long productId){
		productDAO.deleteById(productId);
		return ResponseEntity.ok(null);
	}
	
	@PutMapping
	public ResponseEntity<Product> updateProduct(@RequestBody Product newProduct){
		Optional<Product> oldProduct=productDAO.findById(newProduct.getId()); //optional nos protege de que la query nos devuelva un valor nulo
		if(oldProduct.isPresent()) {
			productDAO.save(newProduct); //si existe la id, el metodo save hace un UPDATE en vez de un INSERT
			return ResponseEntity.ok(newProduct);
		}else {
			return ResponseEntity.notFound().build();
		}
	}
	
	//@RequestMapping(path="hello", method=RequestMethod.GET) ESTA ES LA FORMA ANTIGUA, en vez de path se puede poner value tambien
	@GetMapping(path= "/hello")
	public String hello() {
		return "hola jjejjejej";
	}
	

	//findAll con Paginacion
	//ejemplo de request: http://localhost:8080/products/paginaProd?page=0&size=3  -> page indica la pagina y size el numero de registros que queremos de dicha pagina
	@GetMapping(path="/paginaProd")
	public List<Product> getProductsPaginable(Pageable pageable){
		return productDAO.findAll(pageable).getContent();
	}
	
}
