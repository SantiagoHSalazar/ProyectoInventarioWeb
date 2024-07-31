package com.tutorial.seguridad.Controladores;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import com.tutorial.seguridad.Modelos.Permiso;
import com.tutorial.seguridad.Repositorios.RepositorioPermisos;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/permiso")

public class ControladorPermisos {
    @Autowired
    private RepositorioPermisos miRepositorioPermisos;

    @GetMapping("")
    public List<Permiso> index(){
        return this.miRepositorioPermisos.findAll();
    }

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping
    public Permiso create(@RequestBody Permiso infoPermisos){
        return this.miRepositorioPermisos.save(infoPermisos);
    }

    @GetMapping("{id}")
    public Permiso show(@PathVariable String id){
        Permiso PermisoActual=this.miRepositorioPermisos
                .findById(id)
                .orElse(null);
        return PermisoActual;
    }

    @PutMapping("{id}")
    public Permiso update(@PathVariable String id,@RequestBody  Permiso infoPermiso){
        Permiso PermisoActual=this.miRepositorioPermisos
                .findById(id)
                .orElse(null);
        if (PermisoActual!=null){
            PermisoActual.setUrl(infoPermiso.getUrl());
            return this.miRepositorioPermisos.save(PermisoActual);
        }else{
            return  null;
        }
    }

    @ResponseStatus(HttpStatus.NO_CONTENT)
    @DeleteMapping("{id}")
    public void delete(@PathVariable String id){
        Permiso PermisoActual=this.miRepositorioPermisos
                .findById(id)
                .orElse(null);
        if (PermisoActual!=null){
            this.miRepositorioPermisos.delete(PermisoActual);
        }
    }

    public String convertirSHA256(String password) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-256");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        byte[] hash = md.digest(password.getBytes());
        StringBuffer sb = new StringBuffer();
        for(byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
