# Modulo: Parseador de output Nmap para reportes ejecutivos con datos críticos de ataque.

import re
from typing import Dict, List, Tuple, Any


class NmapReportParser:
    """Parsea output de Nmap slow comprehensive scan y extrae datos para reportes ejecutivos."""
    
    # Mapeo de servicios conocidos a vectores de ataque y riesgo crítico
    SERVICE_ATTACK_VECTORS = {
        "ftp": {"vectors": ["brute-force", "default-creds", "anonymous-login"], "risk": "Alta", "priority": 1},
        "ssh": {"vectors": ["brute-force", "key-exchange-weakness", "user-enum"], "risk": "Alta", "priority": 1},
        "telnet": {"vectors": ["plaintext-auth", "brute-force", "credential-capture"], "risk": "Crítica", "priority": 0},
        "http": {"vectors": ["web-app-attacks", "default-pages", "directory-traversal"], "risk": "Alta", "priority": 2},
        "https": {"vectors": ["ssl-tls-weak", "certificate-recon", "web-app-attacks"], "risk": "Alta", "priority": 2},
        "smtp": {"vectors": ["open-relay", "user-enum", "header-injection"], "risk": "Media", "priority": 3},
        "pop3": {"vectors": ["brute-force", "plaintext-auth", "user-enum"], "risk": "Alta", "priority": 2},
        "imap": {"vectors": ["brute-force", "plaintext-auth", "user-enum"], "risk": "Alta", "priority": 2},
        "smb": {"vectors": ["null-session", "enumeration", "ransomware-vector"], "risk": "Crítica", "priority": 0},
        "netbios": {"vectors": ["name-resolution", "computer-enumeration"], "risk": "Media", "priority": 3},
        "dns": {"vectors": ["zone-transfer", "dns-enumeration", "cache-poisoning"], "risk": "Media", "priority": 3},
        "sql": {"vectors": ["default-auth", "sql-injection", "credential-compromise"], "risk": "Crítica", "priority": 0},
        "rdp": {"vectors": ["brute-force", "bluekeep", "credential-compromise"], "risk": "Crítica", "priority": 0},
        "vnc": {"vectors": ["brute-force", "no-auth", "credential-capture"], "risk": "Crítica", "priority": 0},
        "snmp": {"vectors": ["default-community", "enumeration", "rce"], "risk": "Alta", "priority": 1},
        "ldap": {"vectors": ["anonymous-bind", "enumeration", "injection"], "risk": "Media", "priority": 3},
        "ntp": {"vectors": ["amplification-ddos", "information-disclosure"], "risk": "Baja", "priority": 4},
        "kerberos": {"vectors": ["kerberoasting", "asrepas", "enumeration"], "risk": "Alta", "priority": 1},
    }

    DB_SERVICE_HINTS = {
        "mysql", "mariadb", "postgres", "postgresql", "mongodb", "mongo", "redis",
        "oracle", "mssql", "sql", "db2", "cassandra", "elasticsearch", "opensearch",
    }
    
    def __init__(self, nmap_output: str):
        """Inicializa el parser con output crudo de Nmap."""
        self.raw_output = nmap_output
        self.host_info = {}
        self.open_ports = []
        self.closed_ports = []
        self.os_info = {}
        self.geoloc_info = {}
        self.cloud_info = {"provider": "Unknown", "resource": "Unknown"}
        self.scan_progress = "Unknown"
        self.asset_profiles = []
        self.parse()
    
    def parse(self):
        """Ejecuta parse completo del output."""
        self._parse_host_info()
        self._parse_ports()
        self._parse_os_detection()
        self._parse_geolocation()
        self._parse_cloud_context()
        self._parse_scan_progress()
        self._build_asset_profiles()
    
    def _parse_host_info(self):
        """Extrae información del host: IP, hostname, latencia."""
        # Buscar línea de "Nmap scan report"
        scan_report_match = re.search(
            r"Nmap scan report for (.+?)\s*$",
            self.raw_output,
            re.MULTILINE
        )
        if scan_report_match:
            host_line = scan_report_match.group(1)
            # Parse: "hostname (ip)" o solo "ip"
            ip_match = re.search(r"\(([^)]+)\)", host_line)
            if ip_match:
                self.host_info["ip"] = ip_match.group(1)
                self.host_info["hostname"] = host_line.replace(f"({ip_match.group(1)})", "").strip()
            else:
                self.host_info["ip"] = host_line.strip()
                self.host_info["hostname"] = host_line.strip()

        if not self.host_info.get("ip"):
            host_scan_match = re.search(
                r"Scanning\s+(.+?)\s+\((\d{1,3}(?:\.\d{1,3}){3})\)\s+\[\d+\s+ports\]",
                self.raw_output,
            )
            if host_scan_match:
                self.host_info["hostname"] = host_scan_match.group(1).strip()
                self.host_info["ip"] = host_scan_match.group(2).strip()

        if not self.host_info.get("ip"):
            ip_scan_match = re.search(r"Scanning\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\[\d+\s+ports\]", self.raw_output)
            if ip_scan_match:
                self.host_info["ip"] = ip_scan_match.group(1).strip()
                self.host_info["hostname"] = ip_scan_match.group(1).strip()
        
        # Buscar latencia "Host is up (X.XXXs latency)"
        latency_match = re.search(r"Host is up \(([^)]+)\)", self.raw_output)
        if latency_match:
            self.host_info["latency"] = latency_match.group(1)
    
    def _parse_ports(self):
        """Extrae puertos abiertos, cerrados y servicios con versiones."""
        # Buscar bloque de puertos entre líneas de resumen
        port_section = re.search(
            r"(?:Not shown:.*?\n)?PORT\s+STATE\s+SERVICE\s+VERSION(.*?)(?:No exact OS|TCP/IP fingerprint|TRACEROUTE|$)",
            self.raw_output,
            re.DOTALL
        )
        
        if port_section:
            port_text = port_section.group(1).strip()
            for line in port_text.split("\n"):
                line = line.strip()
                if not line or line.startswith("|"):
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                port_spec = parts[0]
                state = parts[1]
                service = parts[2] if len(parts) > 2 else "unknown"
                version = " ".join(parts[3:]) if len(parts) > 3 else ""
                port_dict = {
                    "port": port_spec,
                    "state": state,
                    "service": service,
                    "version": version,
                }
                if state == "open":
                    self.open_ports.append(port_dict)
                elif state == "closed":
                    self.closed_ports.append(port_dict)

        discovered = re.findall(
            r"Discovered\s+open\s+port\s+(\d+)/(tcp|udp)\s+on\s+(\d{1,3}(?:\.\d{1,3}){3})",
            self.raw_output,
            re.IGNORECASE,
        )
        for port_num, proto, _ip in discovered:
            p = int(port_num)
            self.open_ports.append({
                "port": f"{p}/{proto.lower()}",
                "state": "open",
                "service": "unknown",
                "version": "",
            })

        unique = {}
        for item in self.open_ports:
            key = (item.get("port", ""), item.get("state", ""), item.get("service", ""))
            if key not in unique:
                unique[key] = item
        self.open_ports = list(unique.values())

    def _parse_cloud_context(self):
        host_blob = " ".join([
            str(self.host_info.get("hostname", "")),
            str(self.host_info.get("ip", "")),
            self.raw_output,
        ]).lower()
        if "amazonaws.com" in host_blob or "ec2-" in host_blob:
            self.cloud_info = {"provider": "AWS", "resource": "EC2/ELB"}
            return
        if "azure" in host_blob or "azureedge" in host_blob or "windows.net" in host_blob:
            self.cloud_info = {"provider": "Azure", "resource": "Azure Service"}
            return
        if "googleusercontent.com" in host_blob or "gcp" in host_blob:
            self.cloud_info = {"provider": "GCP", "resource": "GCP Service"}
            return

    def _parse_scan_progress(self):
        phases = re.findall(r"Initiating\s+(.+?)\s+at\s+\d{2}:\d{2}", self.raw_output)
        if phases:
            self.scan_progress = phases[-1].strip()

    def _classify_asset(self, service: str, port_num: int) -> Dict[str, str]:
        s = str(service or "").lower()
        if any(k in s for k in self.DB_SERVICE_HINTS):
            return {"type": "BBDD", "detail": "Motor de base de datos o almacenamiento"}
        if any(k in s for k in {"http", "https", "api", "proxy", "ftp"}):
            return {"type": "Endpoint/Servicio", "detail": "Servicio expuesto para interacción remota"}
        if any(k in s for k in {"snmp", "printer", "ipp", "modbus", "bacnet"}):
            return {"type": "Dispositivo", "detail": "Interfaz de gestión o dispositivo de red/OT"}
        return {"type": "Activo sin clasificar", "detail": "Nmap no aportó evidencia suficiente para tipificarlo"}

    def _build_asset_profiles(self):
        profiles = []
        for port in self.open_ports:
            port_spec = str(port.get("port", ""))
            match = re.match(r"(\d+)/(tcp|udp)", port_spec)
            port_num = int(match.group(1)) if match else 0
            classification = self._classify_asset(str(port.get("service", "")), port_num)
            profiles.append({
                "host": self.host_info.get("hostname") or self.host_info.get("ip", "Unknown"),
                "ip": self.host_info.get("ip", "Unknown"),
                "port": port_spec,
                "service": port.get("service", "unknown"),
                "asset_type": classification["type"],
                "detail": classification["detail"],
                "cloud_provider": self.cloud_info.get("provider", "Unknown"),
                "cloud_resource": self.cloud_info.get("resource", "Unknown"),
            })
        self.asset_profiles = profiles

    def get_asset_profiles(self) -> List[Dict[str, str]]:
        return self.asset_profiles
    
    def _parse_os_detection(self):
        """Extrae información de detección de SO."""
        # Buscar línea "No exact OS matches"
        os_match = re.search(r"No exact OS matches for host.*", self.raw_output)
        if os_match:
            self.os_info["status"] = "No exact match"
        
        # Buscar línea con "OS:" en el fingerprint
        os_guess = re.search(r"OS:([A-Za-z0-9]+)\s", self.raw_output)
        if os_guess:
            self.os_info["fingerprint_hint"] = os_guess.group(1)
    
    def _parse_geolocation(self):
        """Extrae geolocalización y ASN."""
        # Buscar BGP / ASN
        asn_match = re.search(r"Origin AS:\s*(\d+)\s*-\s*(.+?)\s*-\s*(.+?)\s*,\s*(.+?)$", self.raw_output, re.MULTILINE)
        if asn_match:
            self.geoloc_info["asn"] = asn_match.group(1)
            self.geoloc_info["as_name"] = asn_match.group(2)
            self.geoloc_info["organization"] = asn_match.group(3)
            self.geoloc_info["country"] = asn_match.group(4)
    
    def get_critical_ports(self) -> List[Dict[str, Any]]:
        """Devuelve solo puertos abiertos críticos para ataque, ordenados por prioridad."""
        critical = []
        for port_dict in self.open_ports:
            service_lower = port_dict["service"].lower()
            # Buscar en el mapeo de vectores
            for keyword, attack_info in self.SERVICE_ATTACK_VECTORS.items():
                if keyword in service_lower:
                    port_dict["attack_vectors"] = attack_info["vectors"]
                    port_dict["risk"] = attack_info["risk"]
                    port_dict["priority"] = attack_info["priority"]
                    critical.append(port_dict)
                    break
            else:
                # Si no coincide con vectores conocidos, añadir genéricamente
                port_dict["attack_vectors"] = ["enumeration", "default-config"]
                port_dict["risk"] = "Media"
                port_dict["priority"] = 3
                critical.append(port_dict)
        
        # Ordenar por prioridad (0 = crítica primero)
        critical.sort(key=lambda x: x.get("priority", 999))
        return critical
    
    def to_word_table_data(self) -> Tuple[List[str], List[List[str]]]:
        """Genera datos listos para tabla Word: (headers, rows)."""
        headers = ["Puerto", "Estado", "Servicio", "Versión", "Riesgo", "Vectores de Ataque"]
        rows = []
        
        for port_dict in self.get_critical_ports():
            row = [
                port_dict.get("port", "?"),
                port_dict.get("state", "?"),
                port_dict.get("service", "?"),
                port_dict.get("version", "-"),
                port_dict.get("risk", "Media"),
                ", ".join(port_dict.get("attack_vectors", [])),
            ]
            rows.append(row)
        
        return headers, rows
    
    def get_summary(self) -> Dict[str, Any]:
        """Genera resumen ejecutivo con datos clave para el reporte."""
        return {
            "host": self.host_info.get("hostname") or self.host_info.get("ip", "Unknown"),
            "ip": self.host_info.get("ip", "Unknown"),
            "latency": self.host_info.get("latency", "Unknown"),
            "open_ports_count": len(self.open_ports),
            "closed_ports_count": len(self.closed_ports),
            "os_hint": self.os_info.get("fingerprint_hint", "No detectado"),
            "asn": self.geoloc_info.get("asn", "Unknown"),
            "organization": self.geoloc_info.get("organization", "Unknown"),
            "country": self.geoloc_info.get("country", "Unknown"),
            "cloud_provider": self.cloud_info.get("provider", "Unknown"),
            "cloud_resource": self.cloud_info.get("resource", "Unknown"),
            "scan_progress": self.scan_progress,
            "critical_services": [p["service"] for p in self.get_critical_ports()[:3]],
        }


def parse_nmap_output(nmap_text: str) -> NmapReportParser:
    """Función de conveniencia para parsear output Nmap."""
    return NmapReportParser(nmap_text)
