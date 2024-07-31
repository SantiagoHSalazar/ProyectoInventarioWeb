package com.tutorial.seguridad.Repositorios;
import org.springframework.data.mongodb.repository.MongoRepository;
import com.tutorial.seguridad.Modelos.Permiso;
import org.springframework.data.mongodb.repository.Query;

public interface RepositorioPermisos extends MongoRepository<Permiso,String>{
    @Query("{'url':?0,'metodo':?1}")
    Permiso getPermiso(String url, String metodo);
}
