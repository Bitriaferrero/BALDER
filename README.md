# AUDITORIA

Directorio con el informe de la auditoría de red y el script para repetirla.

## Contenido

| Archivo | Descripción |
|---|---|
| `informe_auditoria_2026-10-19.html` | Informe completo de la auditoría del 19/10/2026, con estilos, colores, tablas, índice y badges de severidad. Se abre en cualquier navegador. |
| `auditoria_red.py` | Script que pide el rango, escanea la red y genera un informe HTML nuevo. |
| `informes/` | Informes y JSON generados por el script. |
| `informes/raw/` | Salidas XML crudas de nmap (descubrimiento, preescaneo, puertos altos y escaneo principal). |

## Requisitos

- Python 3.9 o superior.
- `nmap` instalado y en el `PATH`.
- `curl` (opcional, para comprobar pve-exporter, Promtail, Deluge, etc.).

Instalación en Arch:

```bash
sudo pacman -S nmap curl
```

En Debian/Ubuntu:

```bash
sudo apt install nmap curl
```

No hace falta root. El script usa `nmap -sT` (TCP connect), por lo que funciona como usuario normal. Sin root no hay fingerprint de SO ni escaneo UDP; el SO se infiere por banners y puertos.

## Uso

```bash
cd ~/AUDITORIA
python3 auditoria_red.py
```

El script pregunta:

1. **Rango a auditar** — por defecto `192.168.1.0/24`. Puedes cambiarlo a `10.0.0.0/24`, `192.168.0.0/24`, etc.
2. **¿Escaneo completo?** — `s` escanea los 65535 puertos TCP (más lento); `N` usa el modo rápido.
3. **¿Abrir el informe?** — al terminar.

También acepta argumentos:

```bash
# Modo rápido, sin preguntar por el navegador
python3 auditoria_red.py --range 192.168.1.0/24 --quick --no-browser

# Escaneo completo de todos los puertos TCP
python3 auditoria_red.py --range 192.168.1.0/24 --full --no-browser

# Elegir directorio de salida
python3 auditoria_red.py --range 10.0.0.0/24 --quick -o ~/AUDITORIA/informes
```

Opciones útiles:

| Opción | Efecto |
|---|---|
| `-r`, `--range` | Rango CIDR o IP. |
| `--quick` | Top-1000 puertos TCP + puertos curados de LAN. |
| `--full` | Los 65535 puertos TCP. |
| `--top-ports N` | Cambia el top-N del modo rápido. |
| `--no-scripts` | No ejecuta scripts NSE. |
| `--open` | Abre el informe al terminar. |
| `--no-browser` | No pregunta por abrir el navegador. |
| `-y`, `--yes` | No pide confirmación para rangos públicos (úsalo solo con autorización). |
| `-o`, `--output-dir` | Directorio de salida. |

## Qué hace

1. **Descubrimiento** con `nmap -sn`.
2. **Preescaneo de puertos clave**: SSH, DNS, HTTP/HTTPS, Proxmox (8006/3128/9221), Promtail (9080), Deluge (8112), Jackett (9117), CPE/TR-069 (4008), puertos altos no identificados, etc.
3. **Comprobación de puertos altos** sin fingerprint lento, para no perder dispositivos con servicios desconocidos.
4. **Escaneo principal** del top-1000 (o de todos los puertos con `--full`), excluyendo los ya vistos.
5. **Detección de versiones y scripts NSE seguros**: `banner`, `http-title`, `http-headers`, `ssl-cert`, `ssh-hostkey`, `rpcinfo`.
6. **Enriquecimiento de MAC/OUI** con `ip neigh` y `/usr/share/nmap/nmap-mac-prefixes`, para identificar Proxmox (`BC:24:11`), router ZTE, etc.
7. **Inventario Proxmox** sin autenticación si encuentra `pve-exporter` en `:9221` (clúster, nodos, versión, guests).
8. **Reglas de seguridad**:
   - Proxmox VE 8.x EOL.
   - Promtail 2.x EOL y sin autenticación.
   - pve-exporter sin autenticación.
   - BIND 9.18 EOL y CVEs conocidas.
   - Router ZTE con HTTP/firmware antiguo.
   - Deluge/Jackett por HTTP.
   - rpcbind, CPE/TR-069, gestión de Proxmox expuesta.
   - OpenSSH: regreSSHion y builds atrasados.
   - Ubuntu interim EOL, Caddy sin sitio, puertos altos desconocidos.
9. **Informe HTML** autocontenido (sin dependencias externas) y **JSON** con el resumen.

## Salida

Cada ejecución crea:

```text
informes/informe_<rango>_<fecha_hora>.html
informes/informe_<rango>_<fecha_hora>.json
informes/raw/discovery_<...>.xml
informes/raw/prescan_<...>.xml
informes/raw/unknown_ports_<...>.xml
informes/raw/scan_<...>.xml
```

El HTML incluye:

- Resumen con contadores por severidad.
- Inventario de hosts (IP, MAC/OUI, tipo/SO, puertos, notas).
- Inventario Proxmox (clúster, nodos, versión, guests).
- Hallazgos con evidencia, recomendación y CVEs.
- Comprobaciones que salieron bien.
- Detalle por host con puertos, versiones y scripts NSE.
- Metodología y limitaciones.
- Botón para imprimir o guardar como PDF.

## Limitaciones

- Sin root no hay `-O` (fingerprint de SO) ni escaneo UDP.
- El SO es una inferencia por banners/puertos.
- Las reglas EOL/CVE son heurísticas; confirma siempre con los avisos oficiales.
- La asignación exacta IP → guest Proxmox requiere DHCP o la API con credenciales.
- La exposición desde WAN no se puede comprobar desde la LAN.
- El descubrimiento depende de que los hosts respondan; un equipo que bloquee todo puede no aparecer.
- No se prueban credenciales, no se explotan vulnerabilidades y no se modifica nada.

## Aviso

Usa el script solo en redes propias o con autorización expresa. Un escaneo a rangos públicos puede ser ilegal.

---

## Visor OVERSEER

Esta copia del proyecto incluye un visor web local en `OVERSEER/` que agrega
todos los JSON de `informes/` y muestra la red en una interfaz oscura:

```bash
cd ~/AUDITORIA_PLUS/OVERSEER
./run.sh
# http://127.0.0.1:8770
```

- Columna izquierda: IP, SO y tipo (`Proxmox`, `LXC/VM?`, `LXC`, `VM`…).
- Panel central: resumen general o detalle del host con gráficos y pestañas.
- Histórico entre escaneos y clasificación manual LXC/VM (`annotations.json`).
- No escanea ni modifica nada: solo lee los informes.

Detalles en [`OVERSEER/README.md`](OVERSEER/README.md).
# OVERSEER
