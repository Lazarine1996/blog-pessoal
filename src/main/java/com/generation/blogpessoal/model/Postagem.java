package com.generation.blogpessoal.model;

import java.time.ZonedDateTime;

import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.web.bind.annotation.CrossOrigin;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "tb_postagens")
@CrossOrigin(origins = "*", allowedHeaders = "*")
public class Postagem {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "O atributo título é Obrigatório!")
    @Size(min = 5, max = 100, message = "O atributo título deve conter no mínimo 05 e no máximo 100 caracteres")
    private String titulo;

    @NotBlank(message = "O atributo texto é Obrigatório!")
    @Size(min = 10, max = 1000, message = "O atributo texto deve conter no mínimo 10 e no máximo 1000 caracteres")
    private String texto;

    @UpdateTimestamp
    private ZonedDateTime data;

    @ManyToOne
    @JsonIgnoreProperties("postagem")
    private Tema tema;

    @ManyToOne
    @JsonIgnoreProperties("postagem")
    private Usuario usuario;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getTitulo() {
        return titulo;
    }

    public void setTitulo(String titulo) {
        this.titulo = titulo;
    }

    public String getTexto() {
        return texto;
    }

    public void setTexto(String texto) {
        this.texto = texto;
    }

    public ZonedDateTime getData() {
        return data;
    }

    public void setData(ZonedDateTime data) {
        this.data = data;
    }

    public Tema getTema() {
        return tema;
    }

    public void setTema(Tema tema) {
        this.tema = tema;
    }

    public Usuario getUsuario() {
        return usuario;
    }

    public void setUsuario(Usuario usuario) {
        this.usuario = usuario;
    }
}
