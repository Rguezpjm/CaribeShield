# 🛡️ CaribeShield
**Passive & Active Web Posture Checker**
CaribeShield es una herramienta de **evaluación de postura de seguridad web** que combina técnicas **pasivas y activas** para identificar configuraciones inseguras, superficies de ataque expuestas y vulnerabilidades comunes en aplicaciones y servicios web.

Está pensada para **pentesting autorizado**, auditorías internas, hardening y análisis defensivo.

---

## 🚀 Características

- 🔍 Enumeración pasiva de información (headers, TLS, DNS, Detector de CMS, Detector de Librerias, Enumeración de Directorios, Detector de BD, Detector de WAF ,metadata)
- ⚔️ Pruebas activas controladas: **Aun en Desarrollo**
  - SQL Injection (error-based y blind/time-based)
  - Análisis de tiempos de respuesta
  - Detección de errores comunes de backend
- 📊 Visualización de resultados (gráficas con `matplotlib`)
- 🧪 Generación de tráfico realista (User-Agents y datos con `faker`)
- 👤 Registros de usuarios falsos
- 🧱 Diseño modular y extensible
- 📄 Reportes claros para auditoría técnica

---

## 🧰 Requisitos

- Python **3.9+**
- Sistema operativo: Linux / macOS / Windows

### Dependencias externas
```bash
pip install requests matplotlib numpy faker

Pueden tambien ejecutar el siguiente comando para la instalación de las dependencias de forma automatica.

```bash
pip install -r requirements.txt

### Instalacion
```bash
    git clone https://github.com/tuusuario/CaribeShield.git
    cd CaribeShield
    python3 -m pip install -r requirements.txt
    chmod +x caribeshield.py

### Modo de uso
./caribeshield.py  --> Windows
python3 caribeshield.py --> Linux & Mac
