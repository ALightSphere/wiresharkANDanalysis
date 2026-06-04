
from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from security_analyzer import SecurityEngine


@dataclass
class PacketInfo:
    number: int
    time_epoch: float
    src: str
    dst: str
    protocol: str
    length: int
    summary: str
    src_port: str = ""
    dst_port: str = ""
    tcp_flags: str = ""
    dns_query: str = ""



@dataclass
class FlowStats:
    src: str
    dst: str
    protocol: str
    packets: int = 0
    bytes: int = 0


@dataclass
class MonitorReport:
    source: str
    started_at: str
    finished_at: str
    total_packets: int
    total_bytes: int
    protocol_counter: Dict[str, int]
    host_counter: Dict[str, int]
    flows: List[FlowStats]
    packets: List[PacketInfo]
    alerts: List[str]


def build_tshark_command(
    tshark_path: str,
    *,
    live: bool = False,
    interface: Optional[str] = None,
    pcap: Optional[str] = None,
    duration: Optional[int] = None,
    max_packets: Optional[int] = None,
    bpf_filter: Optional[str] = None,
    display_filter: Optional[str] = None,
) -> List[str]:
    cmd = [tshark_path, "-l"]

    fields = [
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "quote=d",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "frame.protocols",
        "-e", "frame.len",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "_ws.col.Info",
        "-e", "tcp.flags",
        "-e", "dns.qry.name",
    ]

    if live:
        if not interface:
            raise ValueError("Для live capture нужно указать interface")
        cmd += ["-i", interface]
        if duration is not None:
            cmd += ["-a", f"duration:{duration}"]
        if max_packets is not None and max_packets > 0:
            cmd += ["-c", str(max_packets)]
        if bpf_filter:
            cmd += ["-f", bpf_filter]
    else:
        if not pcap:
            raise ValueError("Для анализа файла нужно указать pcap")
        cmd += ["-r", pcap]

    if display_filter:
        cmd += ["-Y", display_filter]

    cmd += fields
    return cmd


def parse_tshark_row(row: List[str]) -> Optional[PacketInfo]:
    if len(row) < 13:
        return None

    try:
        number = int(row[0]) if row[0] else 0
    except ValueError:
        number = 0

    try:
        time_epoch = float(row[1]) if row[1] else 0.0
    except ValueError:
        time_epoch = 0.0

    src = row[2] or row[3] or "unknown"
    dst = row[4] or row[5] or "unknown"

    protocols = row[6] or "UNKNOWN"
    proto_parts = [p for p in protocols.split(":") if p]

    _SKIP = {"data", "ethertype", "eth", "frame", "sll", "sll2",
             "null", "ppp", "chdlc", "fr", "raw", "geneve", "vxlan"}

    protocol = "UNKNOWN"
    for part in reversed(proto_parts):
        if part.lower() not in _SKIP:
            protocol = part.upper()
            break

    try:
        length = int(row[7]) if row[7] else 0
    except ValueError:
        length = 0

    src_port = row[8] or row[10] or ""
    dst_port = row[9] or row[11] or ""
    summary = row[12] or ""
    tcp_flags = row[13] if len(row) > 13 else ""
    dns_query = row[14] if len(row) > 14 else ""
    return PacketInfo(
        number=number,
        time_epoch=time_epoch,
        src=src,
        dst=dst,
        protocol=protocol,
        length=length,
        summary=summary,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        dns_query=dns_query
    )


class TrafficMonitor:
    def __init__(self, byte_alert_threshold: int = 1_000_000, packet_limit: int = 0):
        self.byte_alert_threshold = byte_alert_threshold
        self.packet_limit = packet_limit
        self.protocol_counter: Counter[str] = Counter()
        self.host_counter: Counter[str] = Counter()
        self.flow_map: Dict[Tuple[str, str, str], FlowStats] = {}
        self.packets: List[PacketInfo] = []
        self.alerts: List[str] = []
        self.total_bytes = 0
        self.total_packets = 0
        self.security = SecurityEngine()

    def process_packet(self, pkt: PacketInfo) -> None:

        if pkt.dns_query:
            print(f"[DNS] {pkt.src} -> {pkt.dst} | {pkt.dns_query}")
        if pkt.tcp_flags:
            print(f"[TCP] {pkt.src}:{pkt.src_port} -> {pkt.dst}:{pkt.dst_port} | flags={pkt.tcp_flags}")
        self.total_packets += 1
        self.total_bytes += pkt.length

        self.protocol_counter[pkt.protocol] += 1
        if pkt.src != "unknown":
            self.host_counter[pkt.src] += 1
        if pkt.dst != "unknown":
            self.host_counter[pkt.dst] += 1

        key = (pkt.src, pkt.dst, pkt.protocol)
        if key not in self.flow_map:
            self.flow_map[key] = FlowStats(src=pkt.src, dst=pkt.dst, protocol=pkt.protocol)
        self.flow_map[key].packets += 1
        self.flow_map[key].bytes += pkt.length

        if self.packet_limit == 0 or len(self.packets) < self.packet_limit:
            self.packets.append(pkt)

        if self.flow_map[key].bytes >= self.byte_alert_threshold:
            msg = f"Крупный поток: {pkt.src} -> {pkt.dst}, {pkt.protocol}, {self.flow_map[key].bytes} байт"
            if msg not in self.alerts and len(self.alerts) < 100:
                self.alerts.append(msg)
        sec_alerts = self.security.analyze_packet(pkt)
        for sa in sec_alerts:
            msg = f"[{sa.level}] {sa.category}: {sa.message} (Источник: {sa.source_ip})"
            if msg not in self.alerts:
                self.alerts.append(msg)

    def finalize(self, source: str, started_at: str) -> MonitorReport:
        flows_sorted = sorted(self.flow_map.values(), key=lambda f: (f.bytes, f.packets), reverse=True)
        return MonitorReport(
            source=source,
            started_at=started_at,
            finished_at=datetime.now().isoformat(timespec="seconds"),
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            protocol_counter=dict(self.protocol_counter),
            host_counter=dict(self.host_counter.most_common(50)),
            flows=flows_sorted,
            packets=self.packets,
            alerts=self.alerts,
        )


def ensure_tshark_exists(tshark_path: str) -> str:
    p = Path(tshark_path)
    if p.exists():
        return str(p)
    from shutil import which
    found = which(tshark_path)
    if found:
        return found
    raise FileNotFoundError(
        f"Не найден tshark.exe по пути: {tshark_path}. "
        f"Укажи правильный путь, например D:\\Program Files\\Wireshark\\tshark.exe"
    )


def run_tshark_lines(cmd: List[str]) -> Iterable[List[str]]:
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.stdout is not None
    assert proc.stderr is not None

    try:
        reader = csv.reader(proc.stdout, delimiter="\t", quotechar='"')
        for row in reader:
            if row:
                yield row
    finally:
        proc.stdout.close()
        stderr_text = proc.stderr.read()
        rc = proc.wait()
        if stderr_text.strip():
            print(stderr_text.strip(), file=sys.stderr)


def save_json_report(report: MonitorReport, out_path: str) -> None:
    payload = asdict(report)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def print_summary(report: MonitorReport) -> None:
    print("\n=== ИТОГОВЫЙ ОТЧЁТ ===")
    print(f"Источник: {report.source}")
    print(f"Пакетов обработано: {report.total_packets}")
    print(f"Объём данных: {report.total_bytes} байт")

    print("\nПротоколы:")
    for proto, count in sorted(report.protocol_counter.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {proto:<12} {count}")

    print("\nТоп узлов:")
    for host, count in list(report.host_counter.items())[:10]:
        print(f"  {host:<20} {count}")

    print("\nКрупные потоки:")
    for flow in report.flows[:10]:
        print(f"  {flow.src} -> {flow.dst} | {flow.protocol} | пакетов={flow.packets} | байт={flow.bytes}")

    if report.alerts:
        print("\nПредупреждения:")
        for a in report.alerts[:10]:
            print(f"  {a}")


def plot_charts(report: MonitorReport, out_dir: str, exclude_ips: set = None) -> None:
    import matplotlib.pyplot as plt

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    _exclude = exclude_ips or set()

    if report.protocol_counter:
        labels, values = zip(*sorted(report.protocol_counter.items(), key=lambda x: x[1], reverse=True)[:10])
        plt.figure(figsize=(15, 5))
        plt.bar(labels, values)
        plt.title("Топ протоколов")
        plt.xlabel("Протокол")
        plt.ylabel("Количество пакетов")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(out / "protocols.png", dpi=150)
        plt.close()

    filtered_hosts = [(h, c) for h, c in report.host_counter.items() if h not in _exclude]
    if filtered_hosts:
        labels, values = zip(*filtered_hosts[:10])
        plt.figure(figsize=(15, 5))
        plt.bar(labels, values)
        plt.title("Топ узлов")
        plt.xlabel("IP/Host")
        plt.ylabel("Активность")
        plt.xticks(rotation=45, ha="right")
        plt.tight_layout()
        plt.savefig(out / "hosts.png", dpi=150)
        plt.close()

    top_flows = report.flows[:10]
    if top_flows:
        labels = [f"{f.src[:12]}\n→\n{f.dst[:12]}" for f in top_flows]
        values = [f.bytes for f in top_flows]
        plt.figure(figsize=(15, 5))
        plt.bar(labels, values)
        plt.title("Топ потоков по объёму")
        plt.xlabel("Поток")
        plt.ylabel("Байт")
        plt.xticks(rotation=0)
        plt.tight_layout()
        plt.savefig(out / "flows.png", dpi=150)
        plt.close()

def analyze(
    tshark_path: str,
    *,
    live: bool,
    interface: Optional[str],
    pcap: Optional[str],
    duration: Optional[int],
    max_packets: Optional[int],
    bpf_filter: Optional[str],
    display_filter: Optional[str],
    byte_alert_threshold: int,
) -> MonitorReport:
    tshark_path = ensure_tshark_exists(tshark_path)
    monitor = TrafficMonitor(
        byte_alert_threshold=byte_alert_threshold,
        packet_limit=max_packets if max_packets and max_packets > 0 else 0,
    )
    started_at = datetime.now().isoformat(timespec="seconds")

    cmd = build_tshark_command(
        tshark_path,
        live=live,
        interface=interface,
        pcap=pcap,
        duration=duration,
        max_packets=max_packets,
        bpf_filter=bpf_filter,
        display_filter=display_filter,
    )

    source = f"LIVE: {interface}" if live else f"PCAP: {pcap}"
    print("Запуск tshark:")
    print(" ".join(f'"{x}"' if " " in x else x for x in cmd))
    print()

    for row in run_tshark_lines(cmd):
        pkt = parse_tshark_row(row)
        if pkt is not None:
            monitor.process_packet(pkt)

    return monitor.finalize(source=source, started_at=started_at)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Система мониторинга сетевого трафика на основе Wireshark/tshark",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="Путь к PCAP/PCAPNG файлу")
    src.add_argument("--interface", help="Имя сетевого интерфейса для live capture")

    parser.add_argument("--tshark-path", default=r"D:\Program Files\Wireshark\tshark.exe")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--max-packets", type=int, default=5000)
    parser.add_argument("--bpf-filter", default=None)
    parser.add_argument("--display-filter", default=None)
    parser.add_argument("--byte-alert-threshold", type=int, default=1_000_000)
    parser.add_argument("--out-json", default="report.json")
    parser.add_argument("--out-dir", default="charts")
    parser.add_argument("--no-plots", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        report = analyze(
            args.tshark_path,
            live=args.interface is not None,
            interface=args.interface,
            pcap=args.pcap,
            duration=args.duration if args.interface else None,
            max_packets=args.max_packets if args.interface else None,
            bpf_filter=args.bpf_filter,
            display_filter=args.display_filter,
            byte_alert_threshold=args.byte_alert_threshold,
        )

        save_json_report(report, args.out_json)
        print_summary(report)
        print(f"\nJSON-отчёт сохранён в: {args.out_json}")

        if not args.no_plots:
            plot_charts(report, args.out_dir)
            print(f"Графики сохранены в: {args.out_dir}")

        return 0

    except KeyboardInterrupt:
        print("\nОстановка по запросу пользователя.")
        return 130
    except Exception as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())