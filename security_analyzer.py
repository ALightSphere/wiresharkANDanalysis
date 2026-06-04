
import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set
import ipaddress


@dataclass
class SecurityAlert:
    level: str
    category: str
    message: str
    source_ip: str


_LOCAL_NETS = [
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not any(addr in net for net in _LOCAL_NETS)
    except Exception:
        return False


def _is_internal(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _LOCAL_NETS)
    except Exception:
        return False


def _shannon_entropy(s: str) -> float:
    """Энтропия Шеннона строки (0..~4 для нормальных доменов, >3.5 для Base64/hex)."""
    if not s:
        return 0.0
    freq = Counter(s.lower())
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(1 for c in s if c.isdigit()) / len(s)


def _port_int(port_str: str) -> Optional[int]:
    try:
        return int(port_str)
    except (ValueError, TypeError):
        return None


class DataExfiltrationDetector:
    DNS_TUNNEL_LENGTH = 50          # длина всего DNS-имени
    DNS_ENTROPY_THRESHOLD = 3.5     # энтропия субдомена
    DNS_DIGIT_RATIO = 0.45          # доля цифр в имени
    DNS_SUBDOMAIN_COUNT = 5         # подозрительное число субдоменов
    ICMP_LARGE_BYTES = 512          # ICMP > N байт
    OUTBOUND_MB_THRESHOLD = 50      # МБ на внешний IP за сессию
    HTTP_POST_THRESHOLD = 50_000    # байт POST на внешний IP
    BEACON_MIN_CONTACTS = 8
    BEACON_INTERVAL_TOLERANCE = 0.2

    def __init__(self):
        self._outbound_bytes: Counter = Counter()
        self._outbound_alerted: Set = set()
        self._beacon_times: Dict[tuple, List[float]] = defaultdict(list)

    def analyze(self, pkt) -> List[SecurityAlert]:
        alerts = []
        src, dst = pkt.src, pkt.dst

        if hasattr(pkt, "dns_query") and pkt.dns_query:
            q = pkt.dns_query
            labels = q.split(".")
            subdomain = ".".join(labels[:-2]) if len(labels) > 2 else q

            if len(q) > self.DNS_TUNNEL_LENGTH:
                alerts.append(SecurityAlert(
                    "HIGH", "EXFILTRATION",
                    f"DNS-туннель: длинный запрос ({len(q)} симв.): {q[:60]}…",
                    src,
                ))
            elif _shannon_entropy(subdomain) > self.DNS_ENTROPY_THRESHOLD:
                alerts.append(SecurityAlert(
                    "HIGH", "EXFILTRATION",
                    f"DNS-туннель: высокая энтропия субдомена "
                    f"(H={_shannon_entropy(subdomain):.2f}): {q[:60]}",
                    src,
                ))
            elif _digit_ratio(q) > self.DNS_DIGIT_RATIO:
                alerts.append(SecurityAlert(
                    "MEDIUM", "EXFILTRATION",
                    f"DNS-туннель: подозрительно много цифр в запросе "
                    f"({_digit_ratio(q):.0%}): {q[:60]}",
                    src,
                ))
            elif len(labels) > self.DNS_SUBDOMAIN_COUNT:
                alerts.append(SecurityAlert(
                    "MEDIUM", "EXFILTRATION",
                    f"DNS-туннель: слишком много субдоменов ({len(labels)}): {q[:60]}",
                    src,
                ))

        if pkt.protocol in ("ICMP", "ICMPv6") and pkt.length > self.ICMP_LARGE_BYTES:
            alerts.append(SecurityAlert(
                "MEDIUM", "EXFILTRATION",
                f"ICMP с нетипично большой нагрузкой ({pkt.length} байт) — возможная утечка",
                src,
            ))

        if _is_external(dst):
            key = (src, dst)
            self._outbound_bytes[key] += pkt.length
            threshold_bytes = self.OUTBOUND_MB_THRESHOLD * 1_048_576
            if (self._outbound_bytes[key] >= threshold_bytes
                    and key not in self._outbound_alerted):
                self._outbound_alerted.add(key)
                mb = self._outbound_bytes[key] / 1_048_576
                alerts.append(SecurityAlert(
                    "HIGH", "EXFILTRATION",
                    f"Крупная передача данных наружу: {mb:.1f} МБ → {dst}",
                    src,
                ))

        if (pkt.protocol in ("HTTP", "HTTP2")
                and _is_external(dst)
                and pkt.length > self.HTTP_POST_THRESHOLD
                and hasattr(pkt, "summary")
                and "POST" in (pkt.summary or "")):
            alerts.append(SecurityAlert(
                "HIGH", "EXFILTRATION",
                f"Крупный HTTP POST на внешний сервер ({pkt.length} байт) → {dst}",
                src,
            ))

        if _is_external(dst):
            bkey = (src, dst, _port_int(pkt.dst_port))
            now = pkt.time_epoch
            times = self._beacon_times[bkey]
            times.append(now)
            if len(times) >= self.BEACON_MIN_CONTACTS:
                intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
                if intervals:
                    mean_iv = sum(intervals) / len(intervals)
                    if mean_iv > 0:
                        deviations = [abs(iv - mean_iv) / mean_iv for iv in intervals]
                        avg_dev = sum(deviations) / len(deviations)
                        if avg_dev < self.BEACON_INTERVAL_TOLERANCE and mean_iv < 300:
                            alerts.append(SecurityAlert(
                                "HIGH", "EXFILTRATION",
                                f"Beaconing: {len(times)} обращений к {dst}:{pkt.dst_port} "
                                f"с интервалом ~{mean_iv:.1f}с (отклонение {avg_dev:.0%})",
                                src,
                            ))
                            self._beacon_times[bkey] = times[-3:]

        return alerts
def _is_syn_only(flags: str) -> bool:
    try:
        return bool(int(flags, 16) & 0x002)
    except (ValueError, TypeError):
        return False

class PortScanDetector:
    VERT_PORT_THRESHOLD = 15
    HORIZ_HOST_THRESHOLD = 10
    UDP_PORT_THRESHOLD = 10
    ALERT_THROTTLE = 50

    def __init__(self):
        self._ports_by_src_dst: Dict[tuple, Set[int]] = defaultdict(set)
        self._hosts_by_src_port: Dict[tuple, Set[str]] = defaultdict(set)
        self._udp_ports: Dict[str, Set[int]] = defaultdict(set)
        self._alerted: Dict[tuple, int] = {}

    def _throttle_ok(self, key: tuple, pkt_num: int) -> bool:
        last = self._alerted.get(key, -9999)
        if pkt_num - last >= self.ALERT_THROTTLE:
            self._alerted[key] = pkt_num
            return True
        return False


    def analyze(self, pkt) -> List[SecurityAlert]:
        alerts = []
        src, dst = pkt.src, pkt.dst
        dst_port = _port_int(pkt.dst_port)
        pkt_num = pkt.number

        if dst_port:
            vkey = (src, dst)
            self._ports_by_src_dst[vkey].add(dst_port)
            count = len(self._ports_by_src_dst[vkey])
            if count >= self.VERT_PORT_THRESHOLD and self._throttle_ok(("V", src, dst), pkt_num):
                alerts.append(SecurityAlert(
                    "HIGH", "SCAN",
                    f"Вертикальное сканирование: {count} портов на {dst}",
                    src,
                ))

        if dst_port and _is_internal(dst):
            hkey = (src, dst_port)
            self._hosts_by_src_port[hkey].add(dst)
            count = len(self._hosts_by_src_port[hkey])
            if count >= self.HORIZ_HOST_THRESHOLD and self._throttle_ok(("H", src, dst_port), pkt_num):
                alerts.append(SecurityAlert(
                    "HIGH", "SCAN",
                    f"Горизонтальное сканирование: порт {dst_port} на {count} хостах",
                    src,
                ))

        if pkt.protocol == "UDP" and dst_port:
            self._udp_ports[src].add(dst_port)
            count = len(self._udp_ports[src])
            if count >= self.UDP_PORT_THRESHOLD and self._throttle_ok(("UDP", src), pkt_num):
                alerts.append(SecurityAlert(
                    "MEDIUM", "SCAN",
                    f"UDP-сканирование: {count} UDP-портов",
                    src,
                ))

        return alerts

class DDoSDetector:
    SYN_FLOOD_THRESHOLD = 40
    UDP_FLOOD_THRESHOLD = 60
    ICMP_FLOOD_THRESHOLD = 30
    HTTP_FLOOD_THRESHOLD = 80
    DIST_DDOS_SOURCES = 20
    DIST_DDOS_PKTS = 5

    def __init__(self):
        self._syn_cnt: Counter = Counter()
        self._udp_cnt: Counter = Counter()
        self._icmp_cnt: Counter = Counter()
        self._http_cnt: Counter = Counter()
        self._alerted: Set = set()
        self._dst_sources: Dict[str, Counter] = defaultdict(Counter)

    def analyze(self, pkt) -> List[SecurityAlert]:
        alerts = []
        src, dst = pkt.src, pkt.dst
        flags = getattr(pkt, "tcp_flags", "") or ""

        if _is_syn_only(flags):
            self._syn_cnt[src] += 1
            if (self._syn_cnt[src] == self.SYN_FLOOD_THRESHOLD):
                alerts.append(SecurityAlert(
                    "CRITICAL", "DDOS",
                    f"SYN-флуд: {self._syn_cnt[src]} SYN-пакетов",
                    src,
                ))

        if pkt.protocol == "UDP":
            self._udp_cnt[src] += 1
            if self._udp_cnt[src] == self.UDP_FLOOD_THRESHOLD:
                alerts.append(SecurityAlert(
                    "HIGH", "DDOS",
                    f"UDP-флуд: {self._udp_cnt[src]} UDP-пакетов",
                    src,
                ))

        if pkt.protocol in ("ICMP", "ICMPv6"):
            self._icmp_cnt[src] += 1
            if self._icmp_cnt[src] == self.ICMP_FLOOD_THRESHOLD:
                alerts.append(SecurityAlert(
                    "HIGH", "DDOS",
                    f"ICMP-флуд (ping flood): {self._icmp_cnt[src]} пакетов",
                    src,
                ))

        if pkt.protocol in ("HTTP", "HTTP2"):
            self._http_cnt[src] += 1
            if self._http_cnt[src] == self.HTTP_FLOOD_THRESHOLD:
                alerts.append(SecurityAlert(
                    "HIGH", "DDOS",
                    f"HTTP-флуд: {self._http_cnt[src]} HTTP-запросов",
                    src,
                ))

        self._dst_sources[dst][src] += 1
        sources = self._dst_sources[dst]
        active_sources = sum(1 for c in sources.values() if c >= self.DIST_DDOS_PKTS)
        akey = ("DIST", dst)
        if active_sources >= self.DIST_DDOS_SOURCES and akey not in self._alerted:
            self._alerted.add(akey)
            alerts.append(SecurityAlert(
                "CRITICAL", "DDOS",
                f"Распределённая атака: {active_sources} источников → {dst}",
                dst,
            ))

        return alerts



class BruteForceDetector:
    BRUTE_THRESHOLD = 20

    SERVICE_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        110: "POP3", 143: "IMAP", 389: "LDAP", 445: "SMB",
        1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
        3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        5985: "WinRM", 5986: "WinRM-SSL", 6379: "Redis",
        27017: "MongoDB",
    }

    def __init__(self):
        self._syn_map: Counter = Counter()
        self._alerted: Set = set()

    def analyze(self, pkt) -> List[SecurityAlert]:
        alerts = []
        flags = getattr(pkt, "tcp_flags", "") or ""
        dst_port = _port_int(pkt.dst_port)

        if _is_syn_only(flags) and dst_port in self.SERVICE_PORTS:
            key = (pkt.src, pkt.dst, dst_port)
            self._syn_map[key] += 1
            if self._syn_map[key] == self.BRUTE_THRESHOLD and key not in self._alerted:
                self._alerted.add(key)
                service = self.SERVICE_PORTS[dst_port]
                alerts.append(SecurityAlert(
                    "HIGH", "BRUTE",
                    f"Брутфорс {service} (порт {dst_port}): "
                    f"{self._syn_map[key]} попыток → {pkt.dst}",
                    pkt.src,
                ))

        return alerts



class LateralMovementDetector:
    LATERAL_HOST_THRESHOLD = 5

    ADMIN_PORTS = {
        22: "SSH", 135: "WMI/RPC", 139: "NetBIOS",
        445: "SMB", 3389: "RDP", 5985: "WinRM",
        5986: "WinRM-SSL", 593: "RPC-over-HTTP",
    }

    def __init__(self):
        self._admin_contacts: Dict[str, Set[str]] = defaultdict(set)
        self._alerted: Set = set()

    def analyze(self, pkt) -> List[SecurityAlert]:
        alerts = []
        src, dst = pkt.src, pkt.dst
        dst_port = _port_int(pkt.dst_port)

        if (_is_internal(src) and _is_internal(dst)
                and dst_port in self.ADMIN_PORTS):
            self._admin_contacts[src].add(dst)
            count = len(self._admin_contacts[src])

            if (count >= self.LATERAL_HOST_THRESHOLD
                    and src not in self._alerted):
                self._alerted.add(src)
                services = ", ".join(
                    self.ADMIN_PORTS[_port_int(p)]
                    for p in {dst_port}
                    if _port_int(p) in self.ADMIN_PORTS
                )
                alerts.append(SecurityAlert(
                    "CRITICAL", "LATERAL",
                    f"Боковое перемещение: обращения к admin-портам "
                    f"({self.ADMIN_PORTS.get(dst_port,'?')}) на {count} внутренних хостах",
                    src,
                ))

        return alerts



class C2Detector:
    NORMAL_WEB_PORTS = {80, 443, 8080, 8443, 8888}
    TOR_PORTS = {9001, 9030, 9050, 9150}

    SUSPICIOUS_AGENTS = [
        "python-requests", "python-urllib", "curl/",
        "go-http-client", "wget/", "libwww-perl",
        "powershell", "okhttp", "nmap scripting",
    ]

    SHORT_SESSION_THRESHOLD = 5
    HEARTBEAT_COUNT = 10

    def __init__(self):
        self._nonstd_alerted: Set = set()
        self._tor_alerted: Set = set()
        self._heartbeat: Counter = Counter()
        self._hb_alerted: Set = set()

    def analyze(self, pkt) -> List[SecurityAlert]:
        alerts = []
        src, dst = pkt.src, pkt.dst
        dst_port = _port_int(pkt.dst_port)
        summary = (getattr(pkt, "summary", "") or "").lower()

        if (pkt.protocol in ("HTTP", "HTTP2", "TLS", "SSL")
                and dst_port is not None
                and dst_port not in self.NORMAL_WEB_PORTS
                and _is_external(dst)):
            key = (src, dst, dst_port)
            if key not in self._nonstd_alerted:
                self._nonstd_alerted.add(key)
                alerts.append(SecurityAlert(
                    "MEDIUM", "C2",
                    f"HTTP/TLS на нестандартном порту {dst_port} → {dst}",
                    src,
                ))

        for agent in self.SUSPICIOUS_AGENTS:
            if agent in summary:
                alerts.append(SecurityAlert(
                    "MEDIUM", "C2",
                    f"Подозрительный HTTP User-Agent: '{agent}' → {dst}",
                    src,
                ))
                break

        if dst_port in self.TOR_PORTS and _is_external(dst):
            key = (src, dst)
            if key not in self._tor_alerted:
                self._tor_alerted.add(key)
                alerts.append(SecurityAlert(
                    "HIGH", "C2",
                    f"Обращение к TOR-порту {dst_port} → {dst}",
                    src,
                ))

        if (_is_external(dst)
                and pkt.length <= self.SHORT_SESSION_THRESHOLD
                and pkt.protocol == "TCP"):
            hkey = (src, dst)
            self._heartbeat[hkey] += 1
            if (self._heartbeat[hkey] == self.HEARTBEAT_COUNT
                    and hkey not in self._hb_alerted):
                self._hb_alerted.add(hkey)
                alerts.append(SecurityAlert(
                    "HIGH", "C2",
                    f"C2 heartbeat: {self._heartbeat[hkey]} микропакетов (≤{self.SHORT_SESSION_THRESHOLD}б) → {dst}",
                    src,
                ))

        return alerts

class AnomalyDetector:
    WINDOW = 100
    Z_THRESHOLD = 3.0
    VOLUME_SPIKE = 5.0

    PROTO_STANDARD_PORTS: Dict[str, Set[int]] = {
        "DNS": {53, 5353},
        "HTTP": {80, 8080, 8000},
        "HTTPS": {443, 8443},
        "FTP": {20, 21},
        "SSH": {22},
        "SMTP": {25, 587, 465},
        "TELNET": {23},
        "SNMP": {161, 162},
    }

    def __init__(self):
        self._proto_sizes: Dict[str, List[int]] = defaultdict(list)
        self._size_alerted: Set = set()
        self._proto_port_alerted: Set = set()

    def _running_stats(self, sizes: List[int]):
        n = len(sizes)
        if n < 10:
            return None, None
        mean = sum(sizes) / n
        variance = sum((x - mean) ** 2 for x in sizes) / n
        return mean, math.sqrt(variance)

    def analyze(self, pkt) -> List[SecurityAlert]:
        alerts = []
        src = pkt.src
        proto = pkt.protocol
        dst_port = _port_int(pkt.dst_port)

        self._proto_sizes[proto].append(pkt.length)
        if len(self._proto_sizes[proto]) > self.WINDOW * 2:
            self._proto_sizes[proto] = self._proto_sizes[proto][-self.WINDOW:]

        mean, std = self._running_stats(self._proto_sizes[proto])
        if mean is not None and std is not None and std > 0:
            z = abs(pkt.length - mean) / std
            key = (src, proto, pkt.number // 200)
            if z > self.Z_THRESHOLD and key not in self._size_alerted:
                self._size_alerted.add(key)
                alerts.append(SecurityAlert(
                    "LOW", "ANOMALY",
                    f"Аномальный размер {proto}-пакета: {pkt.length} байт "
                    f"(среднее={mean:.0f}, z={z:.1f}σ)",
                    src,
                ))

        if proto in self.PROTO_STANDARD_PORTS and dst_port is not None:
            std_ports = self.PROTO_STANDARD_PORTS[proto]
            if dst_port not in std_ports:
                key = (src, proto, dst_port)
                if key not in self._proto_port_alerted:
                    self._proto_port_alerted.add(key)
                    alerts.append(SecurityAlert(
                        "MEDIUM", "ANOMALY",
                        f"Протокол {proto} на нестандартном порту {dst_port} "
                        f"(ожидались: {sorted(std_ports)})",
                        src,
                    ))

        return alerts


class CredentialLeakDetector:
    CRED_KEYWORDS = [
        "authorization: basic",
        "password=", "passwd=", "pass=",
        "login=", "user=", "username=",
        "token=", "api_key=", "apikey=",
        "secret=", "auth=", "credential",
    ]
    CLEARTEXT_PROTOS = {"HTTP", "TELNET", "FTP", "SMTP", "POP3", "IMAP", "LDAP"}

    def __init__(self):
        self._alerted: Set = set()

    def analyze(self, pkt) -> List[SecurityAlert]:
        alerts = []
        summary = (getattr(pkt, "summary", "") or "").lower()
        src = pkt.src

        for kw in self.CRED_KEYWORDS:
            if kw in summary:
                key = (src, kw, pkt.protocol)
                if key not in self._alerted:
                    self._alerted.add(key)
                    level = "CRITICAL" if pkt.protocol in self.CLEARTEXT_PROTOS else "HIGH"
                    alerts.append(SecurityAlert(
                        level, "CREDS",
                        f"Возможная утечка учётных данных в {pkt.protocol} "
                        f"(найдено: '{kw}')",
                        src,
                    ))
                break

        if pkt.protocol in self.CLEARTEXT_PROTOS:
            key = (src, pkt.protocol, pkt.dst)
            if key not in self._alerted:
                self._alerted.add(key)
                alerts.append(SecurityAlert(
                    "MEDIUM", "INSECURE",
                    f"Небезопасный протокол {pkt.protocol}: данные передаются в открытом виде",
                    src,
                ))

        return alerts



class SecurityEngine:
    def __init__(self):
        self._exfil = DataExfiltrationDetector()
        self._scan = PortScanDetector()
        self._ddos = DDoSDetector()
        self._brute = BruteForceDetector()
        self._lateral = LateralMovementDetector()
        self._c2 = C2Detector()
        self._anomaly = AnomalyDetector()
        self._creds = CredentialLeakDetector()
        self._smurf_sweep = SmurfAndSweepDetector()

    def analyze_packet(self, pkt) -> List[SecurityAlert]:
        alerts: List[SecurityAlert] = []
        for detector in (
            self._exfil,
            self._scan,
            self._ddos,
            self._brute,
            self._lateral,
            self._c2,
            self._anomaly,
            self._creds,
            self._smurf_sweep,
        ):
            try:
                alerts.extend(detector.analyze(pkt))
            except Exception as e:
                pass
        return alerts



class SmurfAndSweepDetector:
    """
    Smurf: входящие ICMP Echo Reply от МНОЖЕСТВА хостов к одному dst
           (жертва получает лавину ответов от усиления через broadcast).
    Ping sweep: один src рассылает ICMP Echo Request множеству dst
                (горизонтальная разведка активных хостов).
    """
    SMURF_SOURCES_THRESHOLD = 15
    SWEEP_HOSTS_THRESHOLD   = 10

    ECHO_REPLY_MARKERS   = ("echo (ping) reply", "echo reply", "icmp type=0")
    ECHO_REQUEST_MARKERS = ("echo (ping) request", "echo request", "icmp type=8")

    def __init__(self):
        self._reply_sources: Dict[str, Set[str]] = defaultdict(set)
        self._smurf_alerted: Set[str] = set()
        self._sweep_targets: Dict[str, Set[str]] = defaultdict(set)
        self._sweep_alerted: Set[str] = set()

    def analyze(self, pkt) -> List[SecurityAlert]:
        alerts = []
        src, dst = pkt.src, pkt.dst

        if pkt.protocol not in ("ICMP", "ICMPv6"):
            return alerts

        summary_low = (getattr(pkt, "summary", "") or "").lower()

        if any(m in summary_low for m in self.ECHO_REPLY_MARKERS):
            self._reply_sources[dst].add(src)
            count = len(self._reply_sources[dst])
            if count >= self.SMURF_SOURCES_THRESHOLD and dst not in self._smurf_alerted:
                self._smurf_alerted.add(dst)
                alerts.append(SecurityAlert(
                    "CRITICAL", "DDOS",
                    f"Smurf-атака: {count} источников шлют ICMP Echo Reply → {dst} "
                    f"(отражение через broadcast)",
                    dst,
                ))


        if any(m in summary_low for m in self.ECHO_REQUEST_MARKERS):
            self._sweep_targets[src].add(dst)
            count = len(self._sweep_targets[src])
            if count >= self.SWEEP_HOSTS_THRESHOLD and src not in self._sweep_alerted:
                self._sweep_alerted.add(src)
                alerts.append(SecurityAlert(
                    "HIGH", "SCAN",
                    f"Ping sweep: ICMP Echo Request к {count} хостам — разведка сети",
                    src,
                ))

        return alerts