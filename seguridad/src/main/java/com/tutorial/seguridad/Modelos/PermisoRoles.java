package com.tutorial.seguridad.Modelos;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document

public class PermisoRoles {
    @Id
    private String _id;

    @DBRef
    private Roles rol;

    @DBRef
    private Permiso permiso;

    public PermisoRoles(){

    }

    public String get_id() {
        return _id;
    }

    public Roles getRol() {
        return rol;
    }

    public Permiso getPermiso() {
        return permiso;
    }

    public void setRol(Roles rol) {
        this.rol = rol;
    }

    public void setPermiso(Permiso permiso) {
        this.permiso = permiso;
    }
}
