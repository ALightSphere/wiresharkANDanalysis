
from __future__ import annotations

import json
import os
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

_THIS_DIR = Path(__file__).parent
sys.path.insert(0, str(_THIS_DIR))
try:
    import network_traffic_monitor_wireshark as tm
except ImportError as _e:
    messagebox.showerror(
        "Ошибка импорта",
        f"Не удалось импортировать traffic_monitor.py:\n{_e}\n\n"
        "Убедитесь, что traffic_monitor.py находится рядом с traffic_monitor_gui.py",
    )
    sys.exit(1)


BG       = "#0f1117"
BG2      = "#1a1d27"
BG3      = "#22263a"
ACCENT   = "#3b82f6"
ACCENT2  = "#60a5fa"
SUCCESS  = "#22c55e"
WARN     = "#f59e0b"
DANGER   = "#ef4444"
TEXT     = "#e2e8f0"
MUTED    = "#64748b"
BORDER   = "#2d3350"

FONT_MONO  = ("Consolas", 10)
FONT_UI    = ("Segoe UI", 10)
FONT_HEAD  = ("Segoe UI", 11, "bold")
FONT_TITLE = ("Segoe UI", 14, "bold")


def _style_entry(w: tk.Entry) -> None:
    w.config(
        bg=BG3, fg=TEXT, insertbackground=TEXT,
        relief="flat", highlightthickness=1,
        highlightbackground=BORDER, highlightcolor=ACCENT,
        font=FONT_UI,
    )


def _style_btn(w: tk.Button, color: str = ACCENT) -> None:
    w.config(
        bg=color, fg="white", activebackground=ACCENT2,
        activeforeground="white", relief="flat", cursor="hand2",
        font=("Segoe UI", 10, "bold"), bd=0, padx=12, pady=6,
    )


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Network Traffic Monitor")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.geometry("980x760")
        self.minsize(800, 620)

        self._report = None
        self._worker = None
        self._log_q: queue.Queue = queue.Queue()
        self._running = False

        self._build_ui()
        self._poll_log()

    def _refresh_own_ips(self) -> None:
        self._own_ips = self._detect_own_ips()
        ip_display = ", ".join(sorted(self._own_ips)) if self._own_ips else "не найдено"
        self._own_ip_label.config(text=ip_display)

    def _is_own_ip(self, ip: str) -> bool:
        return ip.lower().split('%')[0] in self._own_ips

    def _detect_own_ips(self) -> set:
        import subprocess, re
        own = set()
        try:
            out = subprocess.check_output("ipconfig", shell=True, text=True,
                                          encoding="cp866", errors="replace")
            for line in out.splitlines():
                m = re.search(r'IPv4.*?:\s*([\d.]+)', line)
                if m:
                    own.add(m.group(1))
                m6 = re.search(r'IPv6.*?:\s*([0-9a-fA-F:]+(?:%\w+)?)', line)
                if m6:
                    addr = m6.group(1).split('%')[0].lower()
                    own.add(addr)
        except Exception:
            pass
        return own
    def _build_ui(self) -> None:

        hdr = tk.Frame(self, bg=BG, pady=14)
        hdr.pack(fill="x", padx=24)
        
        self._status_lbl = tk.Label(hdr, text="● готов", bg=BG, fg=SUCCESS, font=FONT_UI)
        self._status_lbl.pack(side="right")

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        main = tk.Frame(self, bg=BG)
        main.pack(fill="both", expand=True, padx=0, pady=0)

        left_col = tk.Frame(main, bg=BG, width=390)
        left_col.pack(side="left", fill="y")
        left_col.pack_propagate(False)

        top_bar = tk.Frame(left_col, bg=BG, padx=16, pady=10)
        top_bar.pack(fill="x")
        self._run_btn_top = tk.Button(
            top_bar,
            text="▶  ЗАПУСТИТЬ АНАЛИЗ",
            command=self._start,
            bg="#16a34a", fg="white",
            activebackground="#15803d", activeforeground="white",
            relief="flat", cursor="hand2", bd=0,
            font=("Segoe UI", 12, "bold"),
            pady=12,
        )
        self._run_btn_top.pack(fill="x")
        tk.Frame(left_col, bg=BORDER, height=1).pack(fill="x")

        self._canvas = tk.Canvas(left_col, bg=BG, bd=0, highlightthickness=0)
        _vsb = tk.Scrollbar(left_col, orient="vertical", command=self._canvas.yview)
        self._canvas.configure(yscrollcommand=_vsb.set)
        _vsb.pack(side="right", fill="y")
        self._canvas.pack(side="left", fill="both", expand=True)

        left = tk.Frame(self._canvas, bg=BG)
        self._left_win = self._canvas.create_window((0, 0), window=left, anchor="nw")

        left.bind("<Configure>",
                  lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<Configure>",
                  lambda e: self._canvas.itemconfig(self._left_win, width=e.width))
        self._canvas.bind_all("<MouseWheel>",
                  lambda e: self._canvas.yview_scroll(-1 * (e.delta // 120), "units"))

        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True, padx=(0, 20), pady=16)

        self._build_left(left)
        self._build_right(right)

    def _section(self, parent: tk.Frame, title: str) -> tk.Frame:
        tk.Label(parent, text=title, bg=BG, fg=ACCENT2, font=FONT_HEAD).pack(
            anchor="w", pady=(12, 4))
        frame = tk.Frame(parent, bg=BG2, padx=14, pady=12, bd=0)
        frame.pack(fill="x")
        return frame

    def _row(self, frame: tk.Frame, label: str) -> tk.Entry:
        tk.Label(frame, text=label, bg=BG2, fg=MUTED, font=FONT_UI, anchor="w").pack(
            fill="x", pady=(6, 1))
        e = tk.Entry(frame, width=38)
        _style_entry(e)
        e.pack(fill="x", ipady=5)
        return e

    def _build_left(self, parent: tk.Frame) -> None:
        sf = self._section(parent, "📂  Источник данных")

        self._mode = tk.StringVar(value="pcap")
        modes = tk.Frame(sf, bg=BG2)
        modes.pack(fill="x", pady=(0, 8))
        for val, lbl in (("pcap", "PCAP-файл"), ("live", "Live capture")):
            rb = tk.Radiobutton(modes, text=lbl, variable=self._mode, value=val,
                                bg=BG2, fg=TEXT, selectcolor=BG3, activebackground=BG2,
                                activeforeground=ACCENT2, font=FONT_UI,
                                command=self._on_mode_change)
            rb.pack(side="left", padx=(0, 16))

        self._pcap_frame = tk.Frame(sf, bg=BG2)
        self._pcap_frame.pack(fill="x")
        tk.Label(self._pcap_frame, text="Путь к файлу:", bg=BG2, fg=MUTED,
                 font=FONT_UI, anchor="w").pack(fill="x", pady=(4, 1))
        pr = tk.Frame(self._pcap_frame, bg=BG2)
        pr.pack(fill="x")
        self._pcap_var = tk.StringVar()
        pe = tk.Entry(pr, textvariable=self._pcap_var, width=28)
        _style_entry(pe)
        pe.pack(side="left", fill="x", expand=True, ipady=5)
        btn = tk.Button(pr, text="…", command=self._browse_pcap, width=3)
        _style_btn(btn, BG3)
        btn.pack(side="left", padx=(4, 0))

        self._live_frame = tk.Frame(sf, bg=BG2)
        self._iface_entry = self._row(self._live_frame, "Интерфейс (напр. eth0 / Wi-Fi):")
        self._dur_entry = self._row(self._live_frame, "Длительность, сек:")
        self._dur_entry.insert(0, "30")
        self._maxpkt_entry = self._row(self._live_frame, "Макс. пакетов:")
        self._maxpkt_entry.insert(0, "5000")
        self._on_mode_change()

        tf = self._section(parent, "⚙️  Пути и параметры")
        tk.Label(tf, text="Путь к tshark:", bg=BG2, fg=MUTED,
                 font=FONT_UI, anchor="w").pack(fill="x", pady=(4, 1))
        tr = tk.Frame(tf, bg=BG2)
        tr.pack(fill="x")
        self._tshark_var = tk.StringVar(value=r"D:\Program Files\Wireshark\tshark.exe")
        te = tk.Entry(tr, textvariable=self._tshark_var, width=28)
        _style_entry(te)
        te.pack(side="left", fill="x", expand=True, ipady=5)
        btn2 = tk.Button(tr, text="…", command=self._browse_tshark, width=3)
        _style_btn(btn2, BG3)
        btn2.pack(side="left", padx=(4, 0))

        self._bpf_entry = self._row(tf, "BPF-фильтр (capture):")
        tk.Label(tf,
                 text="Только для Live capture. Фильтрует пакеты до записи — снижает нагрузку.\n"
                      "Примеры:  tcp port 80  |  udp  |  host 192.168.1.1  |  not arp",
                 bg=BG2, fg=MUTED, font=("Segoe UI", 8), justify="left", anchor="w",
                 ).pack(fill="x", pady=(0, 4))

        self._disp_entry = self._row(tf, "Display-фильтр (Wireshark):")
        tk.Label(tf,
                 text="Для PCAP и Live. Отбирает пакеты из уже захваченных данных.\n"
                      "Примеры:  http  |  dns  |  ip.src==10.0.0.1  |  tcp.port==443",
                 bg=BG2, fg=MUTED, font=("Segoe UI", 8), justify="left", anchor="w",
                 ).pack(fill="x", pady=(0, 4))

        self._thr_entry = self._row(tf, "Порог предупреждения, байт:")
        self._thr_entry.insert(0, "1000000")

        ip_frame = self._section(parent, "🛡️  Фильтрация своих адресов")

        self._own_ips = self._detect_own_ips()
        ip_display = ", ".join(sorted(self._own_ips)) if self._own_ips else "не найдено"
        tk.Label(ip_frame, text="Мои адреса (авто):", bg=BG2, fg=MUTED,
                 font=FONT_UI, anchor="w").pack(fill="x", pady=(4, 1))
        self._own_ip_label = tk.Label(
            ip_frame, text=ip_display, bg=BG2, fg=ACCENT2,
            font=("Segoe UI", 8), anchor="w", wraplength=320, justify="left"
        )
        self._own_ip_label.pack(fill="x")

        btn_refresh = tk.Button(ip_frame, text="🔄 Обновить", command=self._refresh_own_ips)
        _style_btn(btn_refresh, BG3)
        btn_refresh.pack(anchor="w", pady=(6, 0))

        self._hide_sec_own_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            ip_frame,
            text="Скрыть свои IP во вкладке «Безопасность»",
            variable=self._hide_sec_own_var,
            bg=BG2, fg=TEXT, selectcolor=BG3, activebackground=BG2,
            activeforeground=ACCENT2, font=FONT_UI
        ).pack(anchor="w", pady=(8, 0))

        of = self._section(parent, "💾  Сохранение результатов")
        tk.Label(of, text="JSON-отчёт:", bg=BG2, fg=MUTED,
                 font=FONT_UI, anchor="w").pack(fill="x", pady=(4, 1))
        jr = tk.Frame(of, bg=BG2)
        jr.pack(fill="x")
        self._json_var = tk.StringVar(value="report.json")
        je = tk.Entry(jr, textvariable=self._json_var, width=28)
        _style_entry(je)
        je.pack(side="left", fill="x", expand=True, ipady=5)
        btn3 = tk.Button(jr, text="…", command=self._browse_json, width=3)
        _style_btn(btn3, BG3)
        btn3.pack(side="left", padx=(4, 0))

        self._noplots_var = tk.BooleanVar(value=False)
        tk.Checkbutton(of, text="Не строить графики", variable=self._noplots_var,
                       bg=BG2, fg=TEXT, selectcolor=BG3, activebackground=BG2,
                       activeforeground=ACCENT2, font=FONT_UI).pack(anchor="w", pady=(8, 0))

        self._hide_own_ip_var = tk.BooleanVar(value=True)
        tk.Checkbutton(
            of, text="Скрыть свои IP в топе узлов",
            variable=self._hide_own_ip_var,
            bg=BG2, fg=TEXT, selectcolor=BG3, activebackground=BG2,
            activeforeground=ACCENT2, font=FONT_UI
        ).pack(anchor="w", pady=(4, 0))

        self._charts_entry = self._row(of, "Папка для графиков:")
        self._charts_entry.insert(0, "charts")

        tk.Frame(parent, bg=BG, height=12).pack()
        self._open_json_btn = tk.Button(
            parent, text="📄 Открыть JSON", command=self._open_json,
            state="disabled",
        )
        _style_btn(self._open_json_btn, BG3)
        self._open_json_btn.pack(fill="x", pady=(0, 16))

    def _build_right(self, parent: tk.Frame) -> None:
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dark.TNotebook", background=BG, borderwidth=0, tabmargins=0)
        style.configure("Dark.TNotebook.Tab", background=BG2, foreground=MUTED,
                        padding=(16, 7), font=FONT_UI)
        style.map("Dark.TNotebook.Tab",
                  background=[("selected", BG3)],
                  foreground=[("selected", TEXT)])

        nb = ttk.Notebook(parent, style="Dark.TNotebook")
        nb.pack(fill="both", expand=True)

        log_frame = tk.Frame(nb, bg=BG)
        nb.add(log_frame, text=" 📟 Лог ")
        self._log = scrolledtext.ScrolledText(
            log_frame, bg=BG2, fg=TEXT, font=FONT_MONO,
            insertbackground=TEXT, relief="flat", wrap="word",
            state="disabled", bd=0,
        )
        self._log.pack(fill="both", expand=True)
        self._log.tag_config("info",  foreground=TEXT)
        self._log.tag_config("ok",    foreground=SUCCESS)
        self._log.tag_config("warn",  foreground=WARN)
        self._log.tag_config("err",   foreground=DANGER)
        self._log.tag_config("muted", foreground=MUTED)
        sec_frame = tk.Frame(nb, bg=BG)
        nb.add(sec_frame, text=" 🛡️ Безопасность ")

        cols_sec = ("level", "type", "desc", "src")
        self._sec_tree = ttk.Treeview(sec_frame, columns=cols_sec, show="headings", style="Dark.Treeview")

        self._sec_tree.heading("level", text="Уровень")
        self._sec_tree.heading("type", text="Тип")
        self._sec_tree.heading("desc", text="Описание")
        self._sec_tree.heading("src", text="Источник")

        self._sec_tree.column("level", width=80)
        self._sec_tree.column("type", width=100)
        self._sec_tree.column("desc", width=400)

        self._sec_tree.tag_configure("CRITICAL", foreground="#ff4444")
        self._sec_tree.tag_configure("HIGH", foreground="#ff8800")
        self._sec_tree.tag_configure("MEDIUM", foreground="#ffff00")

        self._sec_tree.pack(side="left", fill="both", expand=True)

        sum_frame = tk.Frame(nb, bg=BG)
        nb.add(sum_frame, text=" 📊 Итоги ")
        self._summary = scrolledtext.ScrolledText(
            sum_frame, bg=BG2, fg=TEXT, font=FONT_MONO,
            relief="flat", wrap="word", state="disabled", bd=0,
        )
        self._summary.pack(fill="both", expand=True)

        flow_frame = tk.Frame(nb, bg=BG)
        nb.add(flow_frame, text=" 🌐 Потоки ")

        cols = ("src", "dst", "proto", "pkts", "bytes")
        style.configure("Dark.Treeview",
                         background=BG2, fieldbackground=BG2, foreground=TEXT,
                         rowheight=24, borderwidth=0, font=FONT_MONO)
        style.configure("Dark.Treeview.Heading",
                         background=BG3, foreground=ACCENT2,
                         font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Dark.Treeview", background=[("selected", ACCENT)],
                  foreground=[("selected", "white")])

        self._tree = ttk.Treeview(flow_frame, columns=cols, show="headings",
                                  style="Dark.Treeview")
        for col, hdr, w in zip(cols,
                               ("Источник", "Назначение", "Протокол", "Пакеты", "Байт"),
                               (180, 180, 80, 70, 110)):
            self._tree.heading(col, text=hdr)
            self._tree.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(flow_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        self._nb = nb

    def _on_mode_change(self) -> None:
        if self._mode.get() == "pcap":
            self._pcap_frame.pack(fill="x")
            self._live_frame.pack_forget()
        else:
            self._live_frame.pack(fill="x")
            self._pcap_frame.pack_forget()

    def _browse_pcap(self) -> None:
        p = filedialog.askopenfilename(
            title="Выберите PCAP-файл",
            filetypes=[("PCAP/PCAPNG", "*.pcap *.pcapng"), ("Все файлы", "*.*")],
        )
        if p:
            self._pcap_var.set(p)

    def _browse_tshark(self) -> None:
        p = filedialog.askopenfilename(title="Выберите tshark.exe")
        if p:
            self._tshark_var.set(p)

    def _browse_json(self) -> None:
        p = filedialog.asksaveasfilename(
            title="Сохранить JSON-отчёт",
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("Все файлы", "*.*")],
        )
        if p:
            self._json_var.set(p)

    def _start(self) -> None:
        if self._running:
            self._log_line("Анализ уже выполняется.", "warn")
            return

        live = (self._mode.get() == "live")
        tshark   = self._tshark_var.get().strip()
        pcap     = self._pcap_var.get().strip() if not live else None
        iface    = self._iface_entry.get().strip() if live else None
        bpf      = self._bpf_entry.get().strip() or None
        disp     = self._disp_entry.get().strip() or None
        out_json = self._json_var.get().strip() or "report.json"
        out_dir  = self._charts_entry.get().strip() or "charts"

        try:
            dur    = int(self._dur_entry.get() or 30) if live else None
            maxpkt = int(self._maxpkt_entry.get() or 5000) if live else None
            thr    = int(self._thr_entry.get() or 1_000_000)
        except ValueError as exc:
            messagebox.showerror("Ошибка", f"Неверное числовое значение: {exc}")
            return

        if not tshark:
            messagebox.showwarning("Внимание", "Укажите путь к tshark.")
            return
        if live and not iface:
            messagebox.showwarning("Внимание", "Укажите имя интерфейса для live capture.")
            return
        if not live and not pcap:
            messagebox.showwarning("Внимание", "Выберите PCAP-файл.")
            return

        self._clear_results()
        self._set_running(True)
        self._nb.select(0)
        self._log_line(f"{'Live capture' if live else 'PCAP-анализ'} запущен…", "ok")

        params = dict(
            tshark_path=tshark, live=live, interface=iface, pcap=pcap,
            duration=dur, max_packets=maxpkt, bpf_filter=bpf,
            display_filter=disp, byte_alert_threshold=thr,
        )
        no_plots = self._noplots_var.get()
        exclude_ips = self._own_ips.copy() if self._hide_own_ip_var.get() else set()
        self._worker_thread = threading.Thread(
            target=self._run_worker,
            args=(params, out_json, out_dir, no_plots, exclude_ips),
            daemon=True,
        )
        self._worker_thread.start()

    def _run_worker(self, params, out_json, out_dir, no_plots, exclude_ips) -> None:
        try:
            import io

            class QueueWriter(io.TextIOBase):
                def __init__(self, q, tag):
                    self.q, self.tag = q, tag
                def write(self, s):
                    if s.strip():
                        self.q.put((s.rstrip(), self.tag))
                    return len(s)

            old_stdout, old_stderr = sys.stdout, sys.stderr
            sys.stdout = QueueWriter(self._log_q, "info")
            sys.stderr  = QueueWriter(self._log_q, "err")
            try:
                report = tm.analyze(**params)
            finally:
                sys.stdout, sys.stderr = old_stdout, old_stderr

            tm.save_json_report(report, out_json)
            self._log_q.put((f"✅ JSON-отчёт сохранён: {out_json}", "ok"))

            if not no_plots:
                try:
                    tm.plot_charts(report, out_dir, exclude_ips=exclude_ips)
                    self._log_q.put((f"📈 Графики сохранены в: {out_dir}", "ok"))
                except Exception as pe:
                    self._log_q.put((f"⚠️ Графики не построены: {pe}", "warn"))

            self._report = report
            self.after(0, self._show_results, report)

        except Exception as exc:
            self._log_q.put((f"❌ Ошибка: {exc}", "err"))
            self.after(0, self._set_running, False)

    def _show_results(self, report) -> None:
        import re
        self._set_running(False)
        self._open_json_btn.config(state="normal")

        lines = [
            "═" * 52,
            f"  Источник      : {report.source}",
            f"  Начало        : {report.started_at}",
            f"  Конец         : {report.finished_at}",
            f"  Всего пакетов : {report.total_packets:,}",
            f"  Всего байт    : {report.total_bytes:,}",
            "═" * 52, "",
            "  ПРОТОКОЛЫ (топ-10):",
        ]
        for proto, cnt in sorted(report.protocol_counter.items(),
                                 key=lambda x: x[1], reverse=True)[:10]:
            lines.append(f"    {proto:<14} {cnt:>8,}")

        lines += ["", "  ТОП УЗЛОВ:"]
        hide_own = self._hide_own_ip_var.get()
        hosts_filtered = [
            (h, c) for h, c in report.host_counter.items()
            if not (hide_own and self._is_own_ip(h))
        ]
        for host, cnt in hosts_filtered[:10]:
            lines.append(f"    {host:<22} {cnt:>6,}")

        if report.alerts:
            lines += ["", "  ⚠  ПРЕДУПРЕЖДЕНИЯ:"]
            for a in report.alerts[:10]:
                lines.append(f"    {a}")
        lines += ["", "  ✅ Анализ завершён."]

        self._summary.config(state="normal")
        self._summary.delete("1.0", "end")
        self._summary.insert("end", "\n".join(lines))
        self._summary.config(state="disabled")

        for row in self._tree.get_children():
            self._tree.delete(row)
        for f in report.flows[:200]:
            self._tree.insert("", "end", values=(
                f.src, f.dst, f.protocol, f"{f.packets:,}", f"{f.bytes:,}",
            ))

        for row in self._sec_tree.get_children():
            self._sec_tree.delete(row)

        hide_sec = self._hide_sec_own_var.get()

        for alert in report.alerts:
            try:
                match = re.match(r"\[(.*?)\] (.*?): (.*) \(Источник: (.*)\)", alert)
                if match:
                    level = match.group(1)
                    category = match.group(2)
                    msg = match.group(3)
                    src = match.group(4)
                    if hide_sec and self._is_own_ip(src):
                        continue
                    self._sec_tree.insert("", "end",
                                          values=(level, category, msg, src),
                                          tags=(level,))
                else:
                    self._sec_tree.insert("", "end",
                                          values=("?", "INFO", alert, "-"))
            except Exception as e:
                print(f"Ошибка парсинга алерта: {e}")
                continue

        self._nb.select(1)
        self._log_line("✅ Анализ завершён. Смотри вкладки «Итоги» и «Потоки».", "ok")
    def _clear_results(self) -> None:
        for w in (self._log, self._summary):
            w.config(state="normal")
            w.delete("1.0", "end")
            w.config(state="disabled")
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._open_json_btn.config(state="disabled")
        self._report = None
        for row in self._sec_tree.get_children():
            self._sec_tree.delete(row)

    def _set_running(self, val: bool) -> None:
        self._running = val
        if val:
            self._run_btn_top.config(text="⏳ Выполняется…", state="disabled", bg="#15803d")
            self._status_lbl.config(text="● анализ…", fg=WARN)
        else:
            self._run_btn_top.config(text="▶  ЗАПУСТИТЬ АНАЛИЗ", state="normal", bg="#16a34a")
            self._status_lbl.config(text="● готов", fg=SUCCESS)

    def _log_line(self, text: str, tag: str = "info") -> None:
        self._log.config(state="normal")
        self._log.insert("end", text + "\n", tag)
        self._log.see("end")
        self._log.config(state="disabled")

    def _poll_log(self) -> None:
        try:
            while True:
                text, tag = self._log_q.get_nowait()
                self._log_line(text, tag)
        except queue.Empty:
            pass
        self.after(100, self._poll_log)

    def _open_json(self) -> None:
        path = self._json_var.get().strip() or "report.json"
        if not Path(path).exists():
            messagebox.showwarning("Файл не найден", f"Файл не найден:\n{path}")
            return
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                import subprocess; subprocess.run(["open", path])
            else:
                import subprocess; subprocess.run(["xdg-open", path])
        except Exception as exc:
            messagebox.showerror("Ошибка", str(exc))


def main() -> None:
    App().mainloop()


if __name__ == "__main__":
    main()