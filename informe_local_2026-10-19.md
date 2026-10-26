# Auditoría local — ASUS-LAPTOP (CachyOS/Arch) — 2026-10-19

Host `192.168.1.130` · kernel `7.2.9-1-cachyos` · análisis **solo lectura** · usuario `rorshach`
Fecha: 2026-10-19 17:59 CEST · uptime 2 d 21 h

## Resumen ejecutivo

**No se detectan indicios de intrusión.** El servicio SSH está deshabilitado y nunca se ha ejecutado,
no hay cuentas sospechosas, ni claves autorizadas, ni persistencia anómala.

| Indicador | Valor |
|---|---|
| Indicios de intrusión | 0 |
| Usuarios humanos | 2 (`rorshach`, `morpheo`) |
| Cuentas `uid=0` | 1 (`root`) |
| Claves autorizadas (`authorized_keys`) | 0 |
| Logins remotos | 0 |
| Hallazgos a revisar (higiene) | 5 |

## Cuentas de usuario

- `root` (uid 0) — shell `/usr/bin/bash`.
- `rorshach` (uid 1000) — home `/home/rorshach`, shell `/bin/fish`, grupos: wheel, docker, libvirt, wireshark, kismet, nopasswdlogin…
- `morpheo` (uid 1001) — home `/home/morpheo`, shell `/usr/bin/zsh`, sin grupos privilegiados.
- ~40 cuentas de servicio con `nologin` (named, dnsmasq, ollama, sddm, systemd-*…).
- Sin UIDs ni nombres duplicados. Sin cuentas `uid=0` adicionales.
- `/etc/passwd` y `/etc/group` sin cambios desde el 10 jul 2026 (instalación).

## Privilegios

| Grupo | Miembro | Riesgo |
|---|---|---|
| wheel | rorshach | Alto — `sudo` (con contraseña) |
| docker | rorshach | Alto — equivalente a root |
| libvirt | rorshach | Medio |
| wireshark, kismet | rorshach | Medio — captura de red |
| nopasswdlogin | rorshach | Bajo — autologin gráfico |

`morpheo` no está en `wheel` ni puede usar `sudo`.

## SSH y acceso remoto

- `openssh 10.5p1-1.1` instalado, pero `sshd`: **disabled + inactive**.
- **No** existen llaves de host `/etc/ssh/ssh_host_*`.
- **No** hay escuchas en `:22`, **ni** procesos `sshd`, **ni** ficheros `authorized_keys`.
- Journal: **cero** eventos SSH (ni `Accepted`, ni `Failed password`, ni `Invalid user`).
- `/var/log/btmp` = 0 bytes (sin intentos fallidos registrados).
- wtmp: solo sesiones locales `tty1` (`rorshach`, `morpheo`); ninguna sesión `pts`/remota.

## Persistencia y servicios

- Sin `cron` (`/etc/cron*` no existe, `crontab` no instalado).
- Timers systemd estándar (logrotate, man-db, fstrim, shadow, archlinux-keyring…).
- Sin `/etc/ld.so.preload` ni `/etc/rc.local`.
- `auditd` activo.

## Procesos, red e integridad

- Sin mineros/backdoors/reverse shells.
- Tráfico de Firefox, Steam, OpenCode, Tailscale y Ollama.
- Escuchas: `ollama 127.0.0.1:11434`, `steam 0.0.0.0:27036` (LAN), Tailscale y puertos locales. Nada expuesto a Internet.
- Conexión Tailscale DERP (`95.216.195.133:80`) — normal.
- SUID/SGID: todos de paquetes oficiales. `/tmp` y `/dev/shm`: solo memoria compartida de apps.
- `pacman -Qkk`: incidencias solo en ficheros de configuración esperados (`/etc/sudoers`, `/etc/pam.d/sudo`) y en el SUID `ssh-keysign` (no legible sin root → falso positivo).

## Hallazgos y recomendaciones

1. **[Medio]** `rorshach` en grupo `docker` → root efectivo. Salir del grupo o usar Docker rootless.
2. **[Medio]** Autologin de sesión (`nopasswdlogin`): robo físico = acceso. Activar bloqueo y valorar quitar autologin.
3. **[Bajo]** Grupos `wireshark`/`kismet` (captura de red).
4. **[Bajo]** Carpeta `0_PASSWORDS` en el home: usar gestor de credenciales.
5. **[Informativo]** Falta visibilidad de `shadow`, `btmp`, `sudoers` y `/root` sin `sudo`.

### Checklist para cerrar (con root)

```sh
sudo awk -F: '($2==""){print "SIN PASSWORD:",$1}' /etc/shadow
sudo chage -l rorshach; sudo chage -l morpheo
sudo cat /etc/sudoers; sudo ls -la /etc/sudoers.d/
sudo -l -U rorshach
sudo lastb -a | head -40
sudo ls -la /root/.ssh 2>/dev/null
```

## Limitaciones

- Ejecutada sin privilegios: no se leyó `/etc/shadow`, `/var/log/btmp`, `/root` ni `sudoers`.
- `lastlog` no instalado y `/var/log/lastlog` a 0 bytes.
- No se inspeccionó el home/historial de `morpheo`.
- Línea base puntual; no sustituye a un IDS/EDR.

---
*Informe: `informe_local_2026-10-19.html` · Script: `auditoria_local.sh`. Uso en equipos propios y autorizados.*
