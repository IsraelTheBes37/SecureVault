# SecureVault 🔐

**SecureVault** es un proyecto académico de ciberseguridad que consiste en una aplicación web para gestionar credenciales de forma segura. Está desplegada mediante Docker Compose y utiliza varios servicios conectados a través de una red interna.

El proyecto aplica diferentes medidas de seguridad relacionadas con la autenticación, el cifrado, las comunicaciones HTTPS y el aislamiento de los servicios.

> **Aviso:** SecureVault es un proyecto educativo. Antes de utilizarlo en un entorno real, sería necesario realizar una auditoría de seguridad y una revisión adicional de su configuración.

## 1. Objetivos del proyecto

- Desplegar una aplicación web mediante contenedores Docker.
- Separar la aplicación, la base de datos y el servidor web.
- Utilizar HTTPS para proteger las comunicaciones.
- Aplicar medidas de autenticación y autenticación en dos factores (2FA).
- Cifrar información sensible almacenada en la aplicación.
- Facilitar la instalación y reproducción del proyecto en otros equipos.

## 2. Tecnologías utilizadas

| Tecnología | Función |
|---|---|
| Docker | Ejecuta los servicios en contenedores aislados. |
| Docker Compose | Gestiona los servicios y su configuración conjunta. |
| Python y Flask | Implementan la aplicación web. |
| Gunicorn | Ejecuta la aplicación Flask. |
| PostgreSQL | Almacena los datos de la aplicación. |
| Nginx | Actúa como proxy inverso y gestiona el acceso HTTP/HTTPS. |
| Argon2 | Se utiliza para el almacenamiento seguro de contraseñas mediante hashes. |
| Fernet | Permite cifrar y descifrar información. |
| PyOTP y QRCode | Facilitan la configuración de la autenticación en dos factores. |

## 3. Arquitectura

El proyecto está formado por tres servicios principales:

1. **Nginx:** recibe las conexiones de los usuarios y las dirige a la aplicación. Redirige las conexiones HTTP a HTTPS.
2. **Aplicación SecureVault:** procesa las solicitudes y contiene la lógica de autenticación y gestión de credenciales.
3. **PostgreSQL:** almacena los datos y no publica su puerto directamente en el equipo anfitrión.

Los servicios se comunican mediante una red interna de Docker.

```text
             Usuario
                |
                | HTTPS :8443
                v
        +------------------+
        |      Nginx       |
        |   Proxy inverso  |
        +------------------+
                |
                | Red interna
                v
        +------------------+
        | Flask + Gunicorn |
        |       :5000      |
        +------------------+
                |
                | Red interna
                v
        +------------------+
        |    PostgreSQL    |
        |       :5432      |
        +------------------+
```

## 4. Requisitos previos

Antes de comenzar, es necesario disponer de:

- Git.
- Docker Engine o Docker Desktop con soporte para Docker Compose.
- OpenSSL.
- Un terminal Linux, Ubuntu o WSL2, o un entorno equivalente con las herramientas necesarias.

Se pueden comprobar las instalaciones con:

```bash
git --version
docker --version
docker compose version
openssl version
```

## 5. Clonar el repositorio

Clona el repositorio de GitHub y accede al directorio del proyecto:

```bash
git clone https://github.com/IsraelTheBes37/SecureVault
cd securevault
```

Si el repositorio tiene otro nombre o está alojado en otra dirección, utiliza su URL real.

Comprueba que aparecen los archivos del proyecto:

```bash
ls -la
```

Deben encontrarse, entre otros, `Dockerfile`, `docker-compose.yml`, `.env.example`, `app/` y `nginx/`.

## 6. Configurar el archivo `.env`

El archivo `.env` contiene las variables de configuración y los secretos necesarios para ejecutar la aplicación.

Crea una copia de la plantilla:

```bash
cp .env.example .env
```

Abre el archivo para editarlo:

```bash
nano .env
```

### 6.1. Generar `SECRET_KEY`

Esta clave se utiliza para las funciones de seguridad de la sesión de Flask, según la configuración de la aplicación.

Puedes generarla con Python:

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Como alternativa:

```bash
openssl rand -hex 32
```

Copia el resultado en la variable `SECRET_KEY` del archivo `.env`.

### 6.2. Generar `FERNET_KEY`

Esta clave se utiliza para cifrar y descifrar información mediante Fernet. Debe ser una clave válida generada por la biblioteca `cryptography`.

Si no tienes Python y la biblioteca instalada en el equipo, puedes generarla mediante Docker:

```bash
docker run --rm python:3.12.11-slim sh -c "pip install --quiet cryptography && python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
```

Copia el resultado completo en la variable `FERNET_KEY` del archivo `.env`.

**Importante:** `SECRET_KEY` y `FERNET_KEY` son claves diferentes. No utilices el mismo valor para ambas.

Si ya existen datos cifrados con una `FERNET_KEY`, no la cambies sin disponer de un procedimiento de migración, porque los datos cifrados podrían dejar de ser recuperables.

### 6.3. Configurar las demás variables

Revisa todas las variables que aparecen en `.env.example` y configura los valores necesarios. Como mínimo, comprueba las credenciales de PostgreSQL y los puertos publicados.

Ejemplo orientativo:

```dotenv
POSTGRES_DB=securevault
POSTGRES_USER=securevault_user
POSTGRES_PASSWORD=CAMBIA_ESTA_CONTRASENA
SECRET_KEY=PEGA_AQUI_LA_CLAVE_GENERADA
FERNET_KEY=PEGA_AQUI_LA_CLAVE_FERNET
NGINX_PORT=8080
HTTPS_PORT=8443
COOKIE_SECURE=true
```

Este ejemplo no sustituye a `.env.example`: conserva y configura las demás variables que exija la versión actual del proyecto. Si los nombres de las variables o sus usos difieren en el código, sigue la configuración real del repositorio.

Guarda los cambios en Nano con `Ctrl + O`, pulsa `Enter` y sal con `Ctrl + X`.

**No publiques el archivo `.env` en GitHub.** Contiene secretos y credenciales.

## 7. Generar el certificado HTTPS

El proyecto utiliza un certificado autofirmado para las pruebas locales.

Crea el directorio de certificados:

```bash
mkdir -p nginx/certs
```

Genera el certificado y la clave privada:

```bash
openssl req -x509 -nodes -days 365 \
  -newkey rsa:3072 \
  -keyout nginx/certs/localhost.key \
  -out nginx/certs/localhost.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

Protege la clave privada:

```bash
chmod 600 nginx/certs/localhost.key
```

El certificado `localhost.crt` se utiliza para HTTPS y `localhost.key` es su clave privada.

Este certificado está destinado a pruebas locales. El navegador puede mostrar una advertencia porque no está firmado por una autoridad certificadora de confianza.

No compartas la clave privada.

## 8. Validar y arrancar los servicios

Antes de iniciar los contenedores, comprueba la configuración:

```bash
docker compose config --quiet
```

Si no aparece ningún error, construye la imagen de la aplicación e inicia los servicios:

```bash
docker compose up -d --build
```

Comprueba el estado:

```bash
docker compose ps
```

Se espera encontrar los tres servicios:

- `securevault-db-1`: debe aparecer como `healthy` cuando finalice correctamente su comprobación de salud.
- `securevault-app-1`: debe estar en ejecución.
- `securevault-nginx-1`: debe estar en ejecución.

La primera construcción puede tardar más porque Docker necesita descargar imágenes e instalar dependencias.

## 9. Acceder a SecureVault

Abre el navegador y accede a:

- **HTTPS:** https://localhost:8443
- **HTTP:** http://localhost:8080

El acceso HTTP debe redirigir a HTTPS si se mantiene la configuración actual de Nginx.

Debido al certificado autofirmado, el navegador puede mostrar una advertencia de seguridad. Esto es esperado en el entorno local de pruebas; no significa que el certificado sea adecuado para producción.

## 10. Comprobar el funcionamiento

### Comprobar los contenedores

```bash
docker compose ps
```

### Comprobar HTTPS

```bash
curl -k -I https://localhost:8443/login
```

Se espera una respuesta HTTP correcta, normalmente `200 OK`.

### Comprobar la redirección HTTP

```bash
curl -I http://localhost:8080/login
```

Se espera una respuesta de redirección, normalmente `301 Moved Permanently`, hacia la dirección HTTPS.

### Comprobar el estado de la aplicación

```bash
curl -k -i https://localhost:8443/health
```

La ruta `/health` debe devolver una respuesta satisfactoria, por ejemplo `200 OK` y `{"status":"ok"}`.

### Comprobar el usuario de ejecución

```bash
docker compose exec app id
```

La aplicación debe ejecutarse con el usuario no privilegiado configurado en el contenedor. En la configuración validada del proyecto aparece el UID `10001`.

### Pruebas funcionales

Además de las comprobaciones técnicas, prueba desde el navegador:

1. Registrar un usuario.
2. Configurar la autenticación en dos factores, si está habilitada para el usuario.
3. Iniciar sesión.
4. Verificar el acceso al almacén de credenciales.
5. Probar las funciones disponibles, como añadir, consultar o eliminar entradas y cerrar sesión.

Realiza las pruebas únicamente con datos ficticios.

## 11. Comandos de administración

Ver los registros de todos los servicios:

```bash
docker compose logs --tail=100
```

Ver los registros de Nginx:

```bash
docker compose logs --tail=100 nginx
```

Ver los registros de la aplicación:

```bash
docker compose logs --tail=100 app
```

Ver los registros de PostgreSQL:

```bash
docker compose logs --tail=100 db
```

Reiniciar los servicios:

```bash
docker compose restart
```

Detener los servicios sin eliminar los datos persistentes:

```bash
docker compose down
```

Volver a iniciar el proyecto:

```bash
docker compose up -d
```

**Precaución:** no ejecutes `docker compose down -v` salvo que quieras eliminar deliberadamente los volúmenes asociados. En este proyecto, el volumen de PostgreSQL puede contener datos de la aplicación.

## 12. Seguridad aplicada

Entre las medidas incorporadas en el proyecto se encuentran:

- Separación de la aplicación, la base de datos y el proxy inverso.
- Red interna de Docker para la comunicación entre servicios.
- PostgreSQL sin publicación directa de su puerto en el anfitrión.
- HTTPS mediante Nginx.
- Redirección de HTTP a HTTPS.
- Cabeceras HTTP de seguridad.
- Ejecución de la aplicación con un usuario no privilegiado.
- Hash de contraseñas mediante Argon2.
- Cifrado de información mediante Fernet.
- Autenticación en dos factores mediante TOTP.
- Protección CSRF y limitación de solicitudes, según la configuración de Flask.
- Uso de cookies de sesión con atributos de seguridad.

La presencia de estas medidas no garantiza por sí sola que la aplicación sea segura frente a todos los ataques.

## 13. Limitaciones conocidas

- El certificado HTTPS es autofirmado y está pensado para pruebas.
- El proyecto está diseñado con fines educativos y no sustituye a una solución auditada para producción.
- La pérdida de `FERNET_KEY` puede impedir recuperar los datos cifrados.
- Es necesario gestionar las copias de seguridad de PostgreSQL de forma independiente.
- La configuración de seguridad debe revisarse antes de desplegar el proyecto en una red pública.

## 14. Autores

Proyecto académico desarrollado como práctica de despliegue de aplicaciones y aplicación de medidas de ciberseguridad mediante Docker.

**Repositorio:** https://github.com/IsraelTheBes37/SecureVault
