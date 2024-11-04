# Pentesting - Notes

`Pentesting Notes` es una documento donde encontraras comandos para ayudarte rapidamente a realizar pentesting desde lo mas básico a lo avanzado.

## Nmap

1. Usar **-T2** para entornos reales

   ```bash
   nmap -p- --open -T5 -v -n [TARGET_IP] -oG allPorts

2. Si quiere que el escaneo sea muy pero muy rápido (no es aconsejado en pentesting real), utilizar el comando **-sS** (tcp syn port scan) y el parámetro **--min-rate** (controla el número de paquetes que quieres enviar, por ejemplo 5000 por segundo) y el comando **-Pn** (es para evitar el descubrimiento de host mediante la resolución de nombre del protocolo ARP). 

   ```bash
   nmap -p- -sS --min-rate 5000 --open -vvv -n -Pn [TARGET_IP] -oG allPorts 
