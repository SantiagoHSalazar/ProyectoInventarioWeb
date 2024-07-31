package com.tutorial.seguridad.Repositorios;

import org.springframework.data.mongodb.repository.MongoRepository;
import com.tutorial.seguridad.Modelos.Roles;

public interface RepositorioRoles extends MongoRepository<Roles, String> {

}
