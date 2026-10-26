# OVERSEER

Visor web local para los informes que genera `auditoria_red2.py`. Agrega todos los
JSON de `../informes/`, muestra los hosts en una columna a la izquierda (IP, SO y
tipo) y abre un panel central con el detalle, los gráficos y el histórico.

Sin dependencias externas: solo Python 3 (biblioteca estándar) y un navegador.

## Arrancar

```bash
cd ~/AUDITORIA_PLUS/OVERSEER
./run.sh
```

Abre <http://127.0.0.1:8770>. Opciones:

```bash
./run.sh --port 8771        # otro puerto
./run.sh --host 0.0.0.0     # escuchar en la LAN (¡solo en red de confianza!)
python3 server.py --open    # equivalente sin el script
```

El servidor solo lee los informes; no escanea ni modifica nada.

## Generar informes nuevos

Mientras OVERSEER está abierto:

```bash
cd ~/AUDITORIA_PLUS
python3 auditoria_red2.py --range 192.168.1.0/24 --quick --no-browser
```

Al terminar aparece un `informe_*.json` en `informes/`. Pulsa `⟳` o espera 20 s
(autorrefresco) y el host nuevo se incorpora automáticamente.

## Interfaz

| Zona | Contenido |
|---|---|
| Columna izquierda | Un host por fila: punto de severidad, IP, nombre, tipo y SO. |
| Panel central | Resumen general o detalle del host seleccionado. |
| Resumen general | Donut de severidades, tipos, puertos/servicios frecuentes, hosts con más riesgo, escaneos, hallazgos y Proxmox. |
| Detalle de host | Riesgo, KPIs, gráficos, pestañas **Resumen / Puertos / Hallazgos / Historial** (+ **Proxmox** en nodos y guests). |
| Pie | Nº de hosts, informes acumulados y hora de actualización. |

Atajos: `/` buscar, `↑`/`↓` recorrer hosts, `r` recargar, `Esc` limpiar búsqueda.

## Clasificación manual LXC / VM

`auditoria_red2.py` detecta los guests de Proxmox por la MAC `BC:24:11`, pero
**no puede distinguir LXC de VM** desde la red (ambos aparecen como
`Guest Proxmox (LXC/VM)`). En el detalle de cada host hay un formulario
**clasificar** para asignar el tipo (`LXC`, `VM`, `Nodo Proxmox`, etc.) y un
nombre visible. Se guarda en `annotations.json` y nunca se sobrescribe con
escaneos posteriores.

## API

| Ruta | Método | Uso |
|---|---|---|
| `/api/data` | GET | Datos agregados (hosts, hallazgos, global, escaneos). |
| `/api/health` | GET | Comprobación rápida: `{"ok": true, "reports": n}`. |
| `/api/annotations` | POST | Guarda `{"ip": "...", "type": "...", "name": "..."}`. |

## Agregación

- Se leen todos los `../informes/informe_*.json`.
- Para cada IP se conserva el informe más reciente y se acumula el histórico.
- El riesgo es orientativo: `CRÍTICO 30 · ALTO 15 · MEDIO 6 · BAJO 2 · INFO 0`.
- Si un host desaparece de un escaneo, sigue apareciendo con su último estado.

## Estructura

```
OVERSEER/
├── server.py          # servidor HTTP + agregación (stdlib)
├── index.html         # shell de la interfaz
├── styles.css         # tema oscuro inspirado en OpenCode
├── app.js             # render, gráficos, filtros, anotaciones
├── annotations.json   # clasificaciones manuales (se crea al guardar)
├── run.sh             # lanzador
└── README.md
```

> Uso previsto: tu propia red local. No expongas el puerto a Internet.
