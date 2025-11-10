# FullStack 3 - Actividad Sumativa 1

## Recetas del mundo

API desarrollada en Springboot para gestionar recetas.

## Dependencias

* Springboot-starter-web
* Springboot-devtools
* Springboot-starter-data-jpa
* Lombok
* mysql-connector-j
* jjwt-api
* jjwt-impl
* jjwt-jackson

## Configurar variables de entorno para conexión a base de datos MySQL

* Copiar archivo .env.example y renombrar a .env
* Completar las variables de entorno relacionadas con el nombre de la base de datos, nombre de usuario y password.

## Crear contenedor para base de datos MySQL

```
docker compose up -d
```

## Endpoints para ambiente de desarrollo

* POST: Register Request: http://localhost:8080/api/auth/register
* POST: Login Request: http://localhost:8080/api/auth/login
* GET: All Users: http://localhost:8080/api/users

## Ejemplo de Request Body

```json
{
  "username": "veronica",
  "email": "veronica@gmail.com",
  "password": "123456asd"
}
```

## Ejemplo de Login Request

```json
{
  "username": "veronica",
  "password": "123456asd"
}
```
