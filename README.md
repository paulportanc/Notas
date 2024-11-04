# Pentesting - Notes

`Pentesting Notes` es una documento donde encontraras comandos para ayudarte rapidamente a realizar pentesting desde lo mas básico a lo avanzado.

## Nmap

1. **Tipos de escaneos**

`-T5` en entornos reales bajar a `-T2`.

   ```bash
   nmap -p- --open -T5 -v -n [TARGET_IP] -oG allPorts

