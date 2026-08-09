# Security Gates - Configuración Centralizada

Carpeta de referencia con configuraciones avanzadas para cada herramienta del pipeline.
**No reemplaza** los archivos existentes — son configuraciones mejoradas que puedes
adoptar cuando quieras reducir falsos positivos y tunear los thresholds.

## Cuándo usar estas configuraciones

| Situación | Qué usar |
|---|---|
| El pipeline **falla por defecto** (app vulnerable a propósito) | `security-pipeline.yml` actual |
| Quieres **filtrar falsos positivos** y ver solo issues reales | Las configuraciones de esta carpeta |
| Quieres **custom thresholds** por herramienta | Archivos individuales abajo |
| Producción real (nunca con esta app) | Aplicar todas las configuraciones |

## Archivos

```
.github-sec-gates/
├── README.md
├── dependency-check/
│   ├── dependency-check.properties    # Custom config OWASP DC
│   └── suppression.xml                # Falsos positivos (FP)
├── trivy/
│   ├── trivy.yaml                     # Custom scan config
│   └── .trivyignore                   # CVEs ignorados
└── sonarqube/
    ├── sonar-project.properties       # Advanced rules & exclusions
    └── quality-profile.xml            # Custom quality profile (reference)
```

## Cómo integrarlos en el pipeline

Para usar estas configuraciones en lugar de las por defecto, copia los archivos
o actualiza las rutas en `.github/workflows/security-pipeline.yml`:

### Dependency-Check
```yaml
- name: Run Dependency-Check (with suppressions)
  run: |
    dependency-check.sh \
      --scan ./composer.lock \
      --suppression .github-sec-gates/dependency-check/suppression.xml \
      --propertyfile .github-sec-gates/dependency-check/dependency-check.properties \
      --format HTML --format JSON \
      --out reports/dependency-check/
```

### Trivy
```yaml
- name: Trivy FS Scan (custom config)
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: fs
    scan-ref: .
    trivy-config: .github-sec-gates/trivy/trivy.yaml
    format: json
    output: trivy-fs-report.json
```

### SonarQube
```yaml
- name: SonarQube Scan (con perfil custom)
  uses: sonarsource/sonarqube-scan-action@v4
  with:
    args: >
      -Dsonar.projectKey=notesapp
      -Dsonar.qualitygate=.github-sec-gates/sonarqube/quality-profile.xml
```

---

## Filosofía de Security Gates

```
┌─────────────────────────────────────────────┐
│              SECURITY GATES                  │
│                                               │
│  Gate 1: Dependency-Check (SCA)              │
│  ├── Prioridad: CVSS ≥ 9 CRITICAL           │
│  ├── Ignorar: FP confirmados con evidencia   │
│  └── Acción: Bloquear build si CRITICAL      │
│                                               │
│  Gate 2: Trivy (Container + IaC)             │
│  ├── Prioridad: RCE, PrivEsc, Creds expuestos│
│  ├── Ignorar: DoS sin vector de red          │
│  └── Acción: Bloquear si HIGH + fixeable     │
│                                               │
│  Gate 3: SonarQube (SAST)                    │
│  ├── Prioridad: SQLi, XSS, RCE (BLOCKER)    │
│  ├── Ignorar: Code smells en tests           │
│  └── Acción: Quality Gate con thresholds     │
└─────────────────────────────────────────────┘
```
