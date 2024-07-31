package com.tutorial.seguridad.Repositorios;

import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;
import com.tutorial.seguridad.Modelos.PermisoRoles;

public interface RepositorioPermisoRoles extends MongoRepository<PermisoRoles,String>{
    @Query("{'rol.$id': ObjectId(?0),'permiso.$id': ObjectId(?1)}")
    PermisoRoles getPermisoRol(String id_rol,String id_permiso);

}
