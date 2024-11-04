# Pentesting - Notes

`Pentesting Notes` es una documento donde encontraras comandos para ayudarte rapidamente a realizar pentesting desde lo mas básico a lo avanzado.

## Nmap

1. Usar **-T2** para entornos reales

   ```bash
   nmap -p- --open -T5 -v -n [TARGET_IP] -oG allPorts
   ```

2. Si quiere que el escaneo sea muy pero muy rápido (no es aconsejado en pentesting real), utilizar el comando **-sS** (tcp syn port scan) y el parámetro **--min-rate** (controla el número de paquetes que quieres enviar, por ejemplo 5000 por segundo) y el comando **-Pn** (es para evitar el descubrimiento de host mediante la resolución de nombre del protocolo ARP). 

   ```bash
   nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn [TARGET_IP] -oG allPorts
   ```

3. Escaneo de **puertos**

   ```bash
   nmap -sC -sV -p22,80 [TARGET_IP] -oN targeted
   ```

4. Usando **script**

   ```bash
   nmap -sV -vv --script vuln [TARGET_IP]
   ```

## Gobuster

1. Para realizar ataques de **fuerza bruta** contra URI (directorios y archivos), subdominios DNS y nombres de host virtuales

   ```bash
   gobuster -u http://example.com -w wordlist.txt dir
   ```
   ```bash
   gobuster dir -u http://10.10.108.46:3333 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
   ```

## Hydra

1. Para realizar ataques de **fuerza bruta** de contraseñas FTP, SSH

   ```bash
   hydra -t 4 -l <username> -P /usr/share/wordlists/rockyou.txt -vV [TARGET_IP] ftp
   ```
   ```bash
   hydra -t 4 -l <username> -P /usr/share/wordlists/rockyou.txt -vV [TARGET_IP] ssh
   ```
