#!/usr/bin/env bash
# Auditoria local read-only - Arch Linux (cuentas, privilegios, SSH, intrusion)
set +e
export LC_ALL=C

echo "############################################################"
echo "### 0. IDENTIDAD DEL SISTEMA"
echo "############################################################"
date
echo "--- hostname: $(hostname)"
uname -a
echo "--- os-release"
cat /etc/os-release 2>/dev/null
echo "--- uptime / arranque"
uptime
who -b 2>/dev/null
echo

echo "############################################################"
echo "### 1. CUENTAS DE USUARIO (/etc/passwd)"
echo "############################################################"
echo "--- listado completo"
awk -F: '{printf "%-20s uid=%-6s gid=%-6s home=%-28s shell=%s\n",$1,$3,$4,$6,$7}' /etc/passwd
echo
echo "--- usuarios humanos (1000<=uid<65534)"
awk -F: '$3>=1000 && $3<65534 {printf "%-20s uid=%-6s home=%-28s shell=%s\n",$1,$3,$6,$7}' /etc/passwd
echo
echo "--- cuentas con uid=0 (debe ser SOLO root)"
awk -F: '$3==0 {print $0}' /etc/passwd
echo
echo "--- cuentas con shell valida (excluye nologin/false/sync/halt/shutdown)"
awk -F: '$7 !~ /\/(nologin|false|sync|shutdown|halt)$/ {printf "%-20s uid=%-6s shell=%s\n",$1,$3,$7}' /etc/passwd
echo
echo "--- UIDs duplicados"
awk -F: '{print $3}' /etc/passwd | sort -n | uniq -d
echo "(vacio = ninguno)"
echo
echo "--- nombres duplicados"
cut -d: -f1 /etc/passwd | sort | uniq -d
echo "(vacio = ninguno)"
echo
echo "--- permisos y mtime de ficheros de cuentas"
stat -c '%n | mtime=%y | %A %U:%G' /etc/passwd /etc/group /etc/gshadow /etc/shadow /etc/sudoers 2>/dev/null
echo
echo "--- /etc/shadow legible?"
head -1 /etc/shadow >/dev/null 2>&1 && echo "SI (revisar hashes vacios)" || echo "NO (solo root, correcto)"
echo
echo "--- home dirs de usuarios humanos existen?"
for u in $(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd); do
  h=$(getent passwd "$u" | cut -d: -f6)
  if [ -d "$h" ]; then echo "OK    $u -> $h (owner: $(stat -c '%U:%G' "$h"))"; else echo "FALTA $u -> $h"; fi
done
echo

echo "############################################################"
echo "### 2. GRUPOS Y PRIVILEGIOS"
echo "############################################################"
for g in wheel sudo adm root docker libvirt systemd-journal nopasswdlogin; do
  echo "--- grupo $g"
  getent group "$g" 2>/dev/null || echo "(no existe)"
done
echo
echo "--- id de cada usuario humano"
for u in $(awk -F: '$3>=1000 && $3<65534 {print $1}' /etc/passwd); do
  echo "$u: $(id "$u" 2>&1)"
done
echo
echo "--- sudo -n -l (reglas del usuario actual, sin password)"
sudo -n -l 2>&1
echo
echo "--- /etc/sudoers.d"
ls -la /etc/sudoers.d/ 2>/dev/null
echo
echo "--- lineas activas de /etc/sudoers"
grep -Ev '^\s*(#|$)' /etc/sudoers 2>/dev/null || echo "(no legible)"
echo

echo "############################################################"
echo "### 3. HISTORIAL DE SESIONES / LOGINS"
echo "############################################################"
echo "--- last (wtmp) ultimos 60"
last -a -n 60 2>&1
echo
echo "--- who -a"
who -a 2>&1
echo
echo "--- w"
w 2>&1
echo
echo "--- lastb (intentos fallidos, btmp)"
lastb -a -n 60 2>&1
echo
echo "--- lastlog"
lastlog 2>&1 | grep -v 'Never logged in' | head -40
echo

echo "############################################################"
echo "### 4. CONFIGURACION SSH"
echo "############################################################"
echo "--- /etc/ssh/sshd_config (lineas activas)"
grep -Ev '^\s*(#|$)' /etc/ssh/sshd_config 2>/dev/null
echo
echo "--- /etc/ssh/sshd_config.d/*.conf"
for f in /etc/ssh/sshd_config.d/*.conf; do
  [ -e "$f" ] && { echo "[$f]"; grep -Ev '^\s*(#|$)' "$f"; }
done
echo
echo "--- sshd -T (config efectiva; puede requerir root)"
sshd -T 2>&1 | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|challengeresponseauthentication|kbdinteractiveauthentication|allowusers|allowgroups|denyusers|denygroups|maxauthtries|logingracetime|x11forwarding)' || echo "(no disponible sin root)"
echo
echo "--- listeners puerto 22"
ss -tlnp 2>/dev/null | grep -E ':22\b' || echo "(sin listener 22 visible)"
echo
echo "--- procesos sshd"
ps -eo pid,user,etime,cmd 2>/dev/null | grep '[s]shd'
echo
echo "--- sesiones SSH activas (conexiones establecidas a :22)"
ss -tnp 2>/dev/null | grep -E ':22\b' || echo "(ninguna visible)"
echo

echo "############################################################"
echo "### 5. CLAVES AUTORIZADAS Y PERMISOS ~/.ssh"
echo "############################################################"
echo "--- ficheros authorized_keys encontrados"
find /home /root -maxdepth 3 -name 'authorized_keys*' -type f -ls 2>/dev/null
echo
echo "--- huellas (fingerprints) de las claves"
for k in $(find /home /root -maxdepth 3 -name 'authorized_keys*' -type f 2>/dev/null); do
  echo "[$k]"
  ssh-keygen -lf "$k" 2>&1
done
echo
echo "--- permisos de ~/.ssh y contenido"
for h in /home/* /root; do
  if [ -d "$h/.ssh" ]; then
    stat -c '%n %A %U:%G' "$h/.ssh" 2>/dev/null
    stat -c '   %n %A %U:%G' "$h/.ssh"/* 2>/dev/null
  fi
done
echo
echo "--- ssh-agent: claves cargadas"
ssh-add -l 2>&1
echo

echo "############################################################"
echo "### 6. JOURNAL: EVENTOS SSH Y GESTION DE USUARIOS"
echo "############################################################"
if journalctl -n 1 --no-pager >/dev/null 2>&1; then
  echo "system journal: LEGIBLE"
  echo "--- sshd: logins aceptados (ultimos 40)"
  journalctl -u sshd --no-pager -n 2000 2>/dev/null | grep -Ei 'Accepted' | tail -40
  echo
  echo "--- sshd: fallos/invalidos (ultimos 40)"
  journalctl -u sshd --no-pager -n 4000 2>/dev/null | grep -Ei 'Failed|Invalid user|authentication failure' | tail -40
  echo
  echo "--- altas/bajas de usuarios o grupos (ultimos 180 dias)"
  journalctl --no-pager --since "180 days ago" 2>/dev/null | grep -Ei 'useradd|usermod|userdel|groupadd|new user|new group' | tail -40
  echo
  echo "--- sudo/su relevantes (ultimos 40)"
  journalctl --no-pager --since "180 days ago" 2>/dev/null | grep -Ei 'sudo|su\[' | grep -Ei 'session opened|COMMAND|authentication failure' | tail -40
else
  echo "system journal: NO legible (sin permisos: no estas en systemd-journal/adm)"
fi
echo "--- user journal"
journalctl --user -n 1 --no-pager >/dev/null 2>&1 && echo "LEGIBLE" || echo "NO legible"
echo

echo "############################################################"
echo "### 7. PROCESOS Y RED"
echo "############################################################"
echo "--- top 25 por CPU"
ps -eo pid,ppid,user,etime,pcpu,pmem,cmd --sort=-pcpu 2>/dev/null | head -26
echo
echo "--- conexiones establecidas (ss -tunp)"
ss -tunp 2>/dev/null | head -60
echo
echo "--- listeners (ss -tulpn)"
ss -tulpn 2>/dev/null | head -60
echo
echo "--- patrones sospechosos"
ps -eo pid,user,cmd 2>/dev/null | grep -Ei 'xmrig|minerd|kinsing|kdevtmpfsi|masscan|zmap|nc -e|ncat|socat|/dev/tcp|curl[^|]*\| *(ba)?sh|wget[^|]*\| *(ba)?sh' | grep -v grep || echo "(ninguno)"
echo

echo "############################################################"
echo "### 8. PERSISTENCIA (cron, timers, servicios, preload)"
echo "############################################################"
echo "--- systemd timers"
systemctl list-timers --all --no-pager 2>/dev/null | head -40
echo
echo "--- /etc/cron*"
ls -la /etc/cron* 2>/dev/null
echo "--- /var/spool/cron"
ls -laR /var/spool/cron/ 2>/dev/null
echo
echo "--- servicios en ejecucion (system)"
systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -60
echo "--- servicios en ejecucion (usuario)"
systemctl --user list-units --type=service --state=running --no-pager 2>/dev/null | head -40
echo
echo "--- /etc/ld.so.preload"
cat /etc/ld.so.preload 2>/dev/null || echo "(no existe)"
echo "--- /etc/rc.local"
cat /etc/rc.local 2>/dev/null || echo "(no existe)"
echo

echo "############################################################"
echo "### 9. BINARIOS SUID/SGID Y EJECUTABLES EN /tmp"
echo "############################################################"
find /usr /bin /sbin /opt /home -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
echo "--- /tmp y /dev/shm ejecutables"
find /tmp /dev/shm -maxdepth 3 -type f -perm -111 -ls 2>/dev/null || echo "(ninguno)"
echo

echo "############################################################"
echo "### 10. FICHEROS RECIENTES EN HOME (7 dias)"
echo "############################################################"
find /home/rorshach -maxdepth 2 -type f -mtime -7 -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort | tail -40
echo
echo "### FIN DE LA AUDITORIA"
#!/usr/bin/env bash
# Segunda pasada - verificacion SSH, contenedores, integridad
set +e
export LC_ALL=C

echo "############ SSH: INSTALACION Y ESTADO ############"
echo "--- pacman openssh"
pacman -Q openssh 2>&1
echo "--- systemctl is-enabled sshd: $(systemctl is-enabled sshd 2>&1)"
echo "--- systemctl is-active  sshd: $(systemctl is-active sshd 2>&1)"
echo "--- systemctl status sshd"
systemctl status sshd --no-pager 2>&1 | head -12
echo
echo "--- host keys presentes"
ls -la /etc/ssh/ssh_host_* 2>&1
echo
echo "--- journal de la unidad sshd (todo)"
journalctl -u sshd --no-pager 2>&1 | head -30
echo "--- journal por identificador sshd (todo)"
journalctl -t sshd --no-pager 2>&1 | head -30
echo
echo "--- busqueda global de eventos SSH en el journal"
journalctl --no-pager 2>&1 | grep -iE 'sshd|Accepted (password|publickey)|Failed password|Invalid user|authentication failure' | tail -40
echo "(vacio = ningun evento SSH registrado)"
echo

echo "############ ACCESO AL JOURNAL (como) ############"
id -nG
ls -ld /var/log/journal 2>&1
getfacl /var/log/journal 2>&1 | head -20
echo

echo "############ CONTENEDORES ############"
echo "--- docker ps -a"
docker ps -a 2>&1
echo "--- docker images"
docker images 2>&1 | head -20
echo

echo "############ SERVICIO shelly-notifications ############"
systemctl --user cat shelly-notifications.service 2>&1 | head -30
echo "--- paquete propietario"
pacman -Qo /usr/bin/shelly 2>&1; pacman -Qs shelly 2>&1
echo

echo "############ CONEXION TAILSCALE SOSPECHOSA ############"
echo "--- ss filtrado por 95.216.195.133"
ss -tnp 2>&1 | grep '95.216.195.133'
echo "--- interfaz tailscale"
tailscale status 2>&1 | head -20
echo "--- ip de tailscale"
ip -brief addr show tailscale0 2>&1
echo

echo "############ INTEGRIDAD DE PAQUETES CLAVE ############"
echo "--- pacman -Qkk openssh"
pacman -Qkk openssh 2>&1 | tail -15
echo "--- pacman -Qkk sudo"
pacman -Qkk sudo 2>&1 | tail -15
echo "--- herramientas anti-rootkit instaladas?"
pacman -Q rkhunter chkrootkit lynis 2>&1
echo

echo "############ SSH DE OTROS USUARIOS Y HISTORIALES ############"
echo "--- /home/morpheo/.ssh"
ls -la /home/morpheo/.ssh 2>&1
echo "--- historial fish de rorshach: patrones de riesgo"
grep -aiE 'curl .*\| *(ba)?sh|wget .*\| *(ba)?sh|/dev/tcp|nc -e|ncat|base64 -d|chmod \+x.*\.sh|ssh -R|ssh -D' /home/rorshach/.local/share/fish/fish_history 2>/dev/null | tail -20
echo "(vacio = nada destacable)"
echo "--- ultimos comandos del historial fish (10)"
tail -20 /home/rorshach/.local/share/fish/fish_history 2>/dev/null
echo

echo "############ PUERTOS ESCUCHANDO EN TODAS LAS INTERFACES ############"
ss -tulpnH 2>/dev/null | awk '{print $1, $5, $7}' | sort -u
echo

echo "############ FICHEROS MODIFICADOS RECIENTES EN /etc (3 dias) ############"
find /etc -xdev -type f -mtime -3 -printf '%TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort | tail -30
echo

echo "############ RUIDO: servidores web/otros procesos no esperados ############"
ps -eo pid,user,cmd 2>/dev/null | grep -Ei 'nginx|apache|httpd|php-fpm|lighttpd|caddy|node |gunicorn|uwsgi|frp|ngrok|cloudflared|tor|polipo' | grep -v grep || echo "(ninguno)"
echo
echo "### FIN SEGUNDA PASADA"
