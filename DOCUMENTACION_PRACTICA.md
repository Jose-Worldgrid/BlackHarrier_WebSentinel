# Documentacion Practica

## 1. Alcance y uso seguro

Esta guia describe el uso operativo del toolkit para auditorias web autorizadas.

Reglas minimas:

- trabajar solo sobre activos con autorizacion,
- evitar entornos productivos sin ventana de pruebas,
- registrar fecha, alcance y responsable tecnico.

## 2. Puesta en marcha

### 2.1 Instalacion

En Windows:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

### 2.2 Activacion y arranque

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run app.py
```

## 3. Configuracion de IA

### 3.1 Archivo .env

```powershell
Copy-Item .env.example .env
```

Completar en .env:

- AZURE_OPENAI_ENDPOINT
- AZURE_OPENAI_API_KEY
- AZURE_OPENAI_MINI_DEPLOYMENT
- AZURE_OPENAI_MINI_API_VERSION

El proveedor por defecto es:

- AI_AGENT_LLM_PROVIDER=azure_openai

### 3.2 Validacion rapida

El script setup.ps1 comprueba automaticamente:

- dependencias Python clave (openai, python-dotenv),
- disponibilidad de Streamlit,
- y configuracion minima de Azure OpenAI.

## 4. Flujo operativo recomendado

1. Definir objetivo y alcance.
2. Ejecutar reconocimiento completo.
3. Revisar correlacion tecnica de hallazgos.
4. Generar estrategia adaptativa de validacion.
5. Ejecutar pruebas ofensivas controladas.
6. Consolidar evidencias y generar informe final.

## 5. Criterios para reducir falsos positivos

- No confirmar impacto por un unico indicador debil.
- Repetir validaciones con variaciones de contexto.
- Exigir evidencia tecnica reproducible.
- Separar claramente hallazgo potencial de hallazgo confirmado.

## 6. Resultados e informes

El toolkit genera salidas tecnicas y reporte Word orientados a:

- detalle tecnico para equipos de correccion,
- priorizacion por severidad e impacto,
- y trazabilidad de pruebas realizadas.

## 7. Higiene del repositorio

No versionar:

- .env,
- resultados de auditorias,
- logs operativos de ejecucion,
- artefactos temporales de extraccion o consolidacion.

## 8. Troubleshooting rapido

- Si falla Streamlit: reinstalar dependencias en .venv.
- Si IA no responde: validar variables AZURE_OPENAI_*.
- Si faltan herramientas externas: reejecutar setup.ps1 opcion completa.
