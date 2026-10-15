import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from collections import Counter
import csv
import os
import threading
import time
import json

from parser import parse_log_file, parse_log_line
from detector import ThreatDetector, DEFAULT_RULES
from normalizer import normalize_text
from threat_intel import ThreatIntel
from reporter import generate_pdf_report
from dashboard import DashboardWindow
from notifications import notify


APP_TITLE = "Log-Based Threat Detection System"


class App(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title(APP_TITLE)
        self.geometry("1450x900")
        self.minsize(1150, 720)
        self.configure(bg="#020b14")

        # ---------------------------------------------------------
        # CORE DATA
        # ---------------------------------------------------------

        self.detector = ThreatDetector(DEFAULT_RULES.copy())
        self.intel = ThreatIntel()

        self.rows = []
        self.alerts = []
        self.current_file = None

        # ---------------------------------------------------------
        # REAL-TIME WATCHER
        # ---------------------------------------------------------

        self.realtime_running = False
        self.realtime_thread = None
        self.realtime_position = 0
        self.realtime_file_id = None
        self.realtime_buffer = ""

        # ---------------------------------------------------------
        # VARIABLES
        # ---------------------------------------------------------

        self.normalize_var = tk.BooleanVar(value=True)
        self.notify_var = tk.BooleanVar(value=True)

        self.status_var = tk.StringVar(
            value="Ready. Open a log file or load demo logs."
        )

        self.source_var = tk.StringVar(
            value="No log file selected"
        )

        self.filter_var = tk.StringVar(value="All")

        self.total_var = tk.StringVar(value="0")
        self.threat_var = tk.StringVar(value="0")
        self.high_var = tk.StringVar(value="0")
        self.ip_var = tk.StringVar(value="0")

        # ---------------------------------------------------------
        # COLORS
        # ---------------------------------------------------------

        self.bg = "#020b14"
        self.sidebar_bg = "#03121e"
        self.panel = "#061522"
        self.panel2 = "#081b2a"

        self.border = "#073c59"
        self.cyan = "#16d9ff"
        self.blue = "#29a9ff"
        self.green = "#20e070"
        self.red = "#ff5b61"
        self.orange = "#ffae22"
        self.yellow = "#ffd23f"

        self.text = "#e8f4ff"
        self.muted = "#7f9bb0"

        # ---------------------------------------------------------
        # BUILD
        # ---------------------------------------------------------

        self._configure_style()
        self._build_ui()

    # =============================================================
    # STYLE
    # =============================================================

    def _configure_style(self):

        style = ttk.Style(self)

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background=self.panel,
            foreground=self.text,
            fieldbackground=self.panel,
            rowheight=30,
            borderwidth=0,
            relief="flat",
            font=("Segoe UI", 9)
        )

        style.configure(
            "Treeview.Heading",
            background="#082235",
            foreground=self.cyan,
            font=("Segoe UI", 9, "bold"),
            relief="flat"
        )

        style.map(
            "Treeview",
            background=[
                ("selected", "#083b5c")
            ],
            foreground=[
                ("selected", "#ffffff")
            ]
        )

        style.configure(
            "TCombobox",
            fieldbackground=self.panel,
            background=self.panel,
            foreground=self.text,
            arrowcolor=self.cyan
        )

    # =============================================================
    # BUTTON
    # =============================================================

    def _button(
        self,
        parent,
        text,
        command,
        color="#082235",
        width=None
    ):

        options = {
            "text": text,
            "command": command,
            "bg": color,
            "fg": self.text,
            "activebackground": "#0d3b55",
            "activeforeground": "#ffffff",
            "relief": "flat",
            "bd": 0,
            "font": ("Segoe UI", 9, "bold"),
            "cursor": "hand2",
            "padx": 13,
            "pady": 8
        }

        if width:
            options["width"] = width

        btn = tk.Button(parent, **options)
        btn.pack(side="left", padx=(0, 6))

        return btn

    # =============================================================
    # PANEL
    # =============================================================

    def _panel(self, parent, title, accent=None):

        if accent is None:
            accent = self.cyan

        outer = tk.Frame(
            parent,
            bg=self.border,
            bd=0
        )

        inner = tk.Frame(
            outer,
            bg=self.panel
        )

        inner.pack(
            fill="both",
            expand=True,
            padx=1,
            pady=1
        )

        title_label = tk.Label(
            inner,
            text=title,
            bg=self.panel,
            fg=accent,
            font=("Segoe UI", 11, "bold"),
            anchor="w"
        )

        title_label.pack(
            fill="x",
            padx=14,
            pady=(11, 4)
        )

        # Store reference so caller can place widgets inside.
        outer.inner = inner

        return outer

    # =============================================================
    # STAT CARD
    # =============================================================

    def _card(
        self,
        parent,
        title,
        variable,
        color
    ):

        card = tk.Frame(
            parent,
            bg=self.panel,
            highlightbackground=self.border,
            highlightthickness=1,
            bd=0
        )

        card.pack(
            side="left",
            fill="both",
            expand=True,
            padx=5
        )

        tk.Label(
            card,
            text=title,
            bg=self.panel,
            fg="#91aec2",
            font=("Segoe UI", 9, "bold"),
            anchor="w"
        ).pack(
            fill="x",
            padx=16,
            pady=(13, 2)
        )

        tk.Label(
            card,
            textvariable=variable,
            bg=self.panel,
            fg=color,
            font=("Segoe UI", 25, "bold"),
            anchor="w"
        ).pack(
            fill="x",
            padx=16,
            pady=(0, 12)
        )

    # =============================================================
    # SIDEBAR BUTTON
    # =============================================================

    def _sidebar_button(
        self,
        parent,
        text,
        command
    ):

        btn = tk.Button(
            parent,
            text=text,
            command=command,
            bg=self.sidebar_bg,
            fg="#d7e8f5",
            activebackground="#07304a",
            activeforeground=self.cyan,
            relief="flat",
            bd=0,
            anchor="w",
            padx=22,
            pady=10,
            font=("Segoe UI", 10, "bold"),
            cursor="hand2"
        )

        btn.pack(
            fill="x",
            pady=1
        )

        return btn

    # =============================================================
    # MAIN UI
    # =============================================================

    def _build_ui(self):

        # ---------------------------------------------------------
        # HEADER
        # ---------------------------------------------------------

        header = tk.Frame(
            self,
            bg="#020b14",
            height=92
        )

        header.pack(
            fill="x"
        )

        header.pack_propagate(False)

        # Shield icon
        tk.Label(
            header,
            text="◈",
            bg="#020b14",
            fg=self.cyan,
            font=("Segoe UI", 30, "bold")
        ).pack(
            side="left",
            padx=(28, 12)
        )

        title_area = tk.Frame(
            header,
            bg="#020b14"
        )

        title_area.pack(
            side="left",
            pady=17
        )

        tk.Label(
            title_area,
            text="LOG-BASED THREAT DETECTION SYSTEM",
            bg="#020b14",
            fg=self.text,
            font=("Segoe UI", 21, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            title_area,
            text="Real-time Log Analysis  |  Threat Intelligence  |  Attack Detection",
            bg="#020b14",
            fg=self.cyan,
            font=("Segoe UI", 9)
        ).pack(
            anchor="w",
            pady=(3, 0)
        )

        # System status
        status_box = tk.Frame(
            header,
            bg=self.panel,
            highlightbackground=self.border,
            highlightthickness=1,
            padx=18,
            pady=9
        )

        status_box.pack(
            side="right",
            padx=25,
            pady=18
        )

        tk.Label(
            status_box,
            text="● SYSTEM ONLINE",
            bg=self.panel,
            fg=self.green,
            font=("Segoe UI", 10, "bold")
        ).pack(
            anchor="w"
        )

        tk.Label(
            status_box,
            text="Monitoring security events",
            bg=self.panel,
            fg=self.muted,
            font=("Segoe UI", 8)
        ).pack(
            anchor="w"
        )

        # ---------------------------------------------------------
        # MAIN BODY
        # ---------------------------------------------------------

        body = tk.Frame(
            self,
            bg=self.bg
        )

        body.pack(
            fill="both",
            expand=True
        )

        # ---------------------------------------------------------
        # SIDEBAR
        # ---------------------------------------------------------

        sidebar = tk.Frame(
            body,
            bg=self.sidebar_bg,
            width=225,
            highlightbackground=self.border,
            highlightthickness=1
        )

        sidebar.pack(
            side="left",
            fill="y"
        )

        sidebar.pack_propagate(False)

        tk.Label(
            sidebar,
            text="SECURITY CONSOLE",
            bg=self.sidebar_bg,
            fg=self.cyan,
            font=("Segoe UI", 9, "bold"),
            anchor="w"
        ).pack(
            fill="x",
            padx=22,
            pady=(25, 15)
        )

        self._sidebar_button(
            sidebar,
            "⌂   Dashboard",
            self._scroll_top
        )

        self._sidebar_button(
            sidebar,
            "▣   Real-time Monitor",
            self.start_realtime
        )

        self._sidebar_button(
            sidebar,
            "⚠   Threat Detection",
            self.run_detection
        )

        self._sidebar_button(
            sidebar,
            "◉   Threat Intelligence",
            self.show_threat_intel
        )

        self._sidebar_button(
            sidebar,
            "⊗   Block List",
            self.generate_block_list
        )

        self._sidebar_button(
            sidebar,
            "⚙   Detection Rules",
            self.show_rules
        )

       

        separator = tk.Frame(
            sidebar,
            bg=self.border,
            height=1
        )

        separator.pack(
            fill="x",
            padx=20,
            pady=18
        )

        tk.Checkbutton(
            sidebar,
            text="Normalize + decode",
            variable=self.normalize_var,
            bg=self.sidebar_bg,
            fg="#b8ccda",
            selectcolor="#082235",
            activebackground=self.sidebar_bg,
            activeforeground=self.text,
            font=("Segoe UI", 9)
        ).pack(
            anchor="w",
            padx=20,
            pady=3
        )

        tk.Checkbutton(
            sidebar,
            text="Desktop alerts",
            variable=self.notify_var,
            bg=self.sidebar_bg,
            fg="#b8ccda",
            selectcolor="#082235",
            activebackground=self.sidebar_bg,
            activeforeground=self.text,
            font=("Segoe UI", 9)
        ).pack(
            anchor="w",
            padx=20,
            pady=3
        )

        # ---------------------------------------------------------
        # RIGHT CONTENT
        # ---------------------------------------------------------

        self.main_area = tk.Frame(
            body,
            bg=self.bg
        )

        self.main_area.pack(
            side="left",
            fill="both",
            expand=True
        )

        # ---------------------------------------------------------
        # ACTION BAR
        # ---------------------------------------------------------

        actions = tk.Frame(
            self.main_area,
            bg=self.bg
        )

        actions.pack(
            fill="x",
            padx=20,
            pady=(16, 8)
        )

        self._button(
            actions,
            "OPEN LOG",
            self.upload_log,
            "#082235"
        )

        self._button(
            actions,
            "RUN DETECTION",
            self.run_detection,
            "#083c32"
        )

        self._button(
            actions,
            "LOAD DEMO",
            self.load_demo,
            "#102b40"
        )

        self._button(
            actions,
            "WATCH LOG",
            self.start_realtime,
            "#073b3a"
        )

        self._button(
            actions,
            "STOP",
            self.stop_realtime,
            "#481b27"
        )

       
        self._button(
            actions,
            "PDF",
            self.make_report,
            "#25194a"
        )

        self._button(
            actions,
            "CSV",
            self.export_csv,
            "#162d40"
        )

        # Severity filter
        tk.Label(
            actions,
            text="Severity:",
            bg=self.bg,
            fg=self.muted,
            font=("Segoe UI", 9)
        ).pack(
            side="left",
            padx=(18, 5)
        )

        combo = ttk.Combobox(
            actions,
            textvariable=self.filter_var,
            values=[
                "All",
                "HIGH",
                "CRITICAL",
                "MEDIUM",
                "LOW"
            ],
            state="readonly",
            width=11
        )

        combo.pack(
            side="left"
        )

        combo.bind(
            "<<ComboboxSelected>>",
            lambda e: self._refresh_logs_and_alerts()
        )

        # ---------------------------------------------------------
        # STATUS
        # ---------------------------------------------------------

        status = tk.Label(
            self.main_area,
            textvariable=self.status_var,
            bg=self.panel,
            fg=self.cyan,
            anchor="w",
            padx=15,
            pady=9,
            font=("Segoe UI", 9, "bold"),
            highlightbackground=self.border,
            highlightthickness=1
        )

        status.pack(
            fill="x",
            padx=20,
            pady=(0, 5)
        )

        tk.Label(
            self.main_area,
            textvariable=self.source_var,
            bg=self.bg,
            fg=self.muted,
            anchor="w",
            padx=3,
            font=("Segoe UI", 9)
        ).pack(
            fill="x",
            padx=20,
            pady=(0, 5)
        )

        # ---------------------------------------------------------
        # STAT CARDS
        # ---------------------------------------------------------

        cards = tk.Frame(
            self.main_area,
            bg=self.bg
        )

        cards.pack(
            fill="x",
            padx=15,
            pady=5
        )

        self._card(
            cards,
            "TOTAL LOG ENTRIES",
            self.total_var,
            self.cyan
        )

        self._card(
            cards,
            "TOTAL ALERTS",
            self.threat_var,
            self.red
        )

        self._card(
            cards,
            "HIGH / CRITICAL",
            self.high_var,
            self.orange
        )

        self._card(
            cards,
            "UNIQUE SOURCE IPs",
            self.ip_var,
            self.cyan
        )

        # ---------------------------------------------------------
        # MIDDLE AREA
        # ---------------------------------------------------------

        middle = tk.Frame(
            self.main_area,
            bg=self.bg
        )

        middle.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=8
        )

        # ---------------------------------------------------------
        # TOP ROW
        # ---------------------------------------------------------

        top_row = tk.Frame(
            middle,
            bg=self.bg
        )

        top_row.pack(
            fill="both",
            expand=True,
            pady=(0, 8)
        )

        # Threat activity
        activity_panel = self._panel(
            top_row,
            "THREAT ACTIVITY",
            self.cyan
        )

        activity_panel.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 7)
        )

        self.activity_canvas = tk.Canvas(
            activity_panel.inner,
            bg=self.panel,
            highlightthickness=0
        )

        self.activity_canvas.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=(0, 12)
        )

        # Recent alerts
        alerts_panel = self._panel(
            top_row,
            "RECENT THREAT ALERTS",
            self.red
        )

        alerts_panel.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(7, 0)
        )

        self.alerts_list = tk.Listbox(
            alerts_panel.inner,
            bg="#04111d",
            fg="#dcecf7",
            selectbackground="#123b55",
            selectforeground="#ffffff",
            borderwidth=0,
            highlightthickness=0,
            font=("Consolas", 9),
            activestyle="none"
        )

        self.alerts_list.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=(0, 12)
        )

        # ---------------------------------------------------------
        # BOTTOM ROW
        # ---------------------------------------------------------

        bottom_row = tk.Frame(
            middle,
            bg=self.bg
        )

        bottom_row.pack(
            fill="both",
            expand=True
        )

        # Log details
        log_panel = self._panel(
            bottom_row,
            "LOG DETAILS",
            self.cyan
        )

        log_panel.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 7)
        )

        log_frame = tk.Frame(
            log_panel.inner,
            bg=self.panel
        )

        log_frame.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=(0, 10)
        )

        columns = (
            "time",
            "ip",
            "status",
            "request"
        )

        self.log_tree = ttk.Treeview(
            log_frame,
            columns=columns,
            show="headings"
        )

        headings = {
            "time": "TIME",
            "ip": "SOURCE IP",
            "status": "STATUS",
            "request": "REQUEST"
        }

        widths = {
            "time": 180,
            "ip": 130,
            "status": 70,
            "request": 600
        }

        for column in columns:

            self.log_tree.heading(
                column,
                text=headings[column]
            )

            self.log_tree.column(
                column,
                width=widths[column],
                anchor="w"
            )

        self.log_tree.tag_configure(
            "threat",
            background="#25151a",
            foreground="#f4dce0"
        )

        self.log_tree.pack(
            side="left",
            fill="both",
            expand=True
        )

        log_scroll = ttk.Scrollbar(
            log_frame,
            orient="vertical",
            command=self.log_tree.yview
        )

        log_scroll.pack(
            side="right",
            fill="y"
        )

        self.log_tree.configure(
            yscrollcommand=log_scroll.set
        )

        # Top source IPs
        ip_panel = self._panel(
            bottom_row,
            "TOP SOURCE IPs",
            self.blue
        )

        ip_panel.pack(
            side="left",
            fill="both",
            padx=(7, 0)
        )

        ip_panel.config(
            width=250
        )

        ip_panel.pack_propagate(False)

        self.ip_summary = tk.Text(
            ip_panel.inner,
            bg="#04111d",
            fg="#bcd1df",
            borderwidth=0,
            highlightthickness=0,
            font=("Consolas", 9),
            wrap="word"
        )

        self.ip_summary.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=(0, 12)
        )

        # ---------------------------------------------------------
        # DRAW EMPTY ACTIVITY
        # ---------------------------------------------------------

        self.after(
            200,
            self._draw_activity
        )

    # =============================================================
    # SCROLL / DASHBOARD
    # =============================================================

    def _scroll_top(self):

        self.status_var.set(
            "Dashboard ready."
        )

    # =============================================================
    # FILE OPEN
    # =============================================================

    def upload_log(self):

        path = filedialog.askopenfilename(
            title="Select a web/server log file",
            filetypes=[
                ("Log/Text/CSV", "*.log *.txt *.csv"),
                ("All files", "*.*")
            ]
        )

        if not path:
            return

        try:

            self.stop_realtime()

            self.rows = parse_log_file(path)

            self.current_file = path

            stat = os.stat(path)

            self.realtime_position = stat.st_size

            self.realtime_file_id = (
                getattr(stat, "st_dev", 0),
                getattr(stat, "st_ino", 0),
            )

            self.realtime_buffer = ""

            self.source_var.set(
                Path(path).name
            )

            self.alerts = []

            self._update_stats()
            self._refresh_logs_and_alerts()

            self.status_var.set(
                f"Loaded {len(self.rows)} log lines. Click Run Detection."
            )

        except Exception as e:

            messagebox.showerror(
                "File Error",
                str(e)
            )

    # =============================================================
    # DEMO LOGS
    # =============================================================

    def load_demo(self):

        self.stop_realtime()

        self.current_file = None

        demo = [

            '192.168.1.10 - - [08/Oct/2026:10:00:00 +0530] "GET /home HTTP/1.1" 200 512',

            '192.168.1.11 - - [08/Oct/2026:10:01:00 +0530] "POST /login HTTP/1.1" 401 120 "invalid password"',

            '192.168.1.11 - - [08/Oct/2026:10:01:03 +0530] "POST /login HTTP/1.1" 401 120 "authentication failure"',

            '192.168.1.11 - - [08/Oct/2026:10:01:08 +0530] "POST /login HTTP/1.1" 401 120 "login failed"',

            '192.168.1.12 - - [08/Oct/2026:10:02:00 +0530] "GET /search?q=%27%20OR%201%3D1 HTTP/1.1" 400 80',

            '192.168.1.13 - - [08/Oct/2026:10:03:00 +0530] "GET /page?name=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 400 90',

            '192.168.1.14 - - [08/Oct/2026:10:04:00 +0530] "GET /../../etc/passwd HTTP/1.1" 404 70',

            '192.168.1.15 - - [08/Oct/2026:10:05:00 +0530] "GET /.env HTTP/1.1" 403 60',

            '192.168.1.16 - - [08/Oct/2026:10:06:00 +0530] "GET / HTTP/1.1" 200 40 "sqlmap"',

            '192.168.1.18 - - [08/Oct/2026:10:08:00 +0530] "GET /fetch?url=http://169.254.169.254/ HTTP/1.1" 400 80',

            '192.168.1.19 - - [08/Oct/2026:10:09:00 +0530] "GET /search?q=%252e%252e%252fsecret HTTP/1.1" 400 80',

            '192.168.1.20 - - [08/Oct/2026:10:10:00 +0530] "GET /run?cmd=%3Bid HTTP/1.1" 400 80'
        ]

        self.rows = []

        for line in demo:

            row = parse_log_line(line)

            if row:
                self.rows.append(row)

        self.source_var.set(
            "Built-in demo logs (fictional test data)"
        )

        self.alerts = []

        self._update_stats()
        self._refresh_logs_and_alerts()

        self.status_var.set(
            "Demo logs loaded. Click Run Detection."
        )

    # =============================================================
    # STATISTICS
    # =============================================================

    def _update_stats(self):

        self.total_var.set(
            str(len(self.rows))
        )

        self.threat_var.set(
            str(len(self.alerts))
        )

        high_critical = sum(
            1
            for alert in self.alerts
            if alert.get("severity") in ("HIGH", "CRITICAL")
        )

        self.high_var.set(
            str(high_critical)
        )

        self.ip_var.set(
            str(
                len(
                    {
                        r.get("ip")
                        for r in self.rows
                        if r.get("ip") != "N/A"
                    }
                )
            )
        )

    # =============================================================
    # FAILED LOGIN
    # =============================================================

    def _is_failed_login(self, text):

        low = text.lower()

        return (
            any(
                x in low
                for x in (
                    "failed login",
                    "login failed",
                    "invalid password",
                    "authentication failure"
                )
            )
            or
            " 401 " in low
        )

    # =============================================================
    # REFRESH GUI
    # =============================================================

    def _refresh_logs_and_alerts(self):

        # ---------------------------------------------------------
        # LOG TABLE
        # ---------------------------------------------------------

        self.log_tree.delete(
            *self.log_tree.get_children()
        )

        flagged_ips = {
            a["ip"]
            for a in self.alerts
        }

        for i, row in enumerate(self.rows):

            self.log_tree.insert(
                "",
                "end",
                iid=f"log{i}",
                values=(
                    row.get("time", ""),
                    row.get("ip", ""),
                    row.get("status", ""),
                    row.get("request", "")
                ),
                tags=(
                    "threat"
                    if row.get("ip") in flagged_ips
                    else ()
                )
            )

        # ---------------------------------------------------------
        # ALERT LIST
        # ---------------------------------------------------------

        self.alerts_list.delete(
            0,
            tk.END
        )

        selected = self.filter_var.get()

        shown = []

        for alert in self.alerts:

            if (
                selected != "All"
                and alert.get("severity") != selected
            ):
                continue

            shown.append(alert)

            self.alerts_list.insert(
                tk.END,
                f'[{alert["severity"]}] '
                f'{alert["rule"]} — '
                f'{alert["ip"]}'
            )

        if not shown and self.alerts:

            self.alerts_list.insert(
                tk.END,
                "No alerts match the selected filter."
            )

        # ---------------------------------------------------------
        # TOP IPS
        # ---------------------------------------------------------

        counts = Counter(
            a["ip"]
            for a in self.alerts
        )

        self.ip_summary.delete(
            "1.0",
            tk.END
        )

        if counts:

            for ip, count in counts.most_common(10):

                self.ip_summary.insert(
                    tk.END,
                    f"{ip:<18} {count} alert(s)\n"
                )

        else:

            self.ip_summary.insert(
                tk.END,
                "No alerts yet."
            )

        # ---------------------------------------------------------
        # STATS
        # ---------------------------------------------------------

        self._update_stats()

        # ---------------------------------------------------------
        # ACTIVITY
        # ---------------------------------------------------------

        self._draw_activity()

    # =============================================================
    # ACTIVITY GRAPH
    # =============================================================

    def _draw_activity(self):

        if not hasattr(
            self,
            "activity_canvas"
        ):
            return

        canvas = self.activity_canvas

        canvas.delete("all")

        width = canvas.winfo_width()
        height = canvas.winfo_height()

        if width < 100:
            width = 500

        if height < 100:
            height = 250

        # Grid
        for x in range(
            40,
            width - 20,
            50
        ):

            canvas.create_line(
                x,
                25,
                x,
                height - 30,
                fill="#0a2b3e"
            )

        for y in range(
            30,
            height - 20,
            35
        ):

            canvas.create_line(
                20,
                y,
                width - 20,
                y,
                fill="#0a2b3e"
            )

        if not self.alerts:

            canvas.create_text(
                width / 2,
                height / 2,
                text="No threat activity detected",
                fill="#56758a",
                font=("Segoe UI", 10)
            )

            return

        # Build simple activity values
        values = []

        max_points = 18

        if len(self.alerts) <= max_points:

            values = [
                1
                for _ in self.alerts
            ]

        else:

            chunk = max(
                1,
                len(self.alerts) // max_points
            )

            for i in range(
                0,
                len(self.alerts),
                chunk
            ):

                values.append(
                    len(
                        self.alerts[
                            i:i + chunk
                        ]
                    )
                )

                if len(values) >= max_points:
                    break

        max_value = max(
            values
        )

        graph_left = 35
        graph_right = width - 25
        graph_top = 30
        graph_bottom = height - 35

        usable_width = graph_right - graph_left
        usable_height = graph_bottom - graph_top

        bar_width = max(
            10,
            usable_width /
            max(
                1,
                len(values) * 1.7
            )
        )

        gap = bar_width * 0.7

        x = graph_left + 10

        for value in values:

            bar_height = (
                value / max_value
            ) * (
                usable_height - 15
            )

            y1 = graph_bottom - bar_height

            canvas.create_rectangle(
                x,
                y1,
                x + bar_width,
                graph_bottom,
                fill="#0aa8d4",
                outline=""
            )

            x += bar_width + gap

            if x > graph_right:
                break

        canvas.create_text(
            35,
            14,
            text=f"{len(self.alerts)} alert events",
            fill="#7fa9bf",
            anchor="w",
            font=("Segoe UI", 8)
        )

    # =============================================================
    # DETECTION
    # =============================================================

    def run_detection(
        self,
        silent=False
    ):

        if not self.rows:

            if not silent:

                messagebox.showwarning(
                    "No Logs",
                    "Open a log file or load demo logs first."
                )

            return

        self.alerts = []

        seen_rows = set()

        for row in self.rows:
            row_key = (
                row.get("time", ""),
                row.get("ip", ""),
                row.get("request", "")
            )

            if row_key in seen_rows:
                continue

            seen_rows.add(row_key)

            request = row.get(
                "request",
                ""
            )

            if self.normalize_var.get():

                text = normalize_text(
                    request
                )

            else:

                text = request

            matches = self.detector.detect(
                text
            )

            # IOC
            if self.intel.is_malicious_ip(
                row.get("ip", "")
            ):

                matches.append(
                    {
                        "rule":
                            "Threat Intelligence IOC",
                        "severity":
                            "HIGH",
                        "match":
                            f"Known malicious IP: "
                            f'{row.get("ip", "")}'
                    }
                )

            for match in matches:

                self.alerts.append(
                    {
                        "rule":
                            match["rule"],

                        "time":
                            row.get("time", ""),

                        "ip":
                            row.get("ip", "N/A"),

                        "severity":
                            match["severity"],

                        "snippet":
                            request[:240],

                        "match":
                            match["match"]
                    }
                )

        self._add_failed_login_threshold_alerts()

        self._refresh_logs_and_alerts()

        self.status_var.set(
            f"Analysis complete: "
            f"{len(self.alerts)} alert(s) "
            f"from {len(self.rows)} log lines."
        )

        if not silent:

            messagebox.showinfo(
                "Detection complete",
                f"Detected {len(self.alerts)} alert(s)."
            )

            if self.notify_var.get():

                try:

                    notify(
                        "Threat Detection Complete",
                        f"{len(self.alerts)} alert(s) detected."
                    )

                except Exception:
                    pass

    # =============================================================
    # FAILED LOGIN THRESHOLD
    # =============================================================

    def _add_failed_login_threshold_alerts(self):
        counts = Counter()
        first_event = {}

        for row in self.rows:
            if self._is_failed_login(row.get("raw", "")):
                ip = row.get("ip", "N/A")
                counts[ip] += 1

                if ip not in first_event:
                    first_event[ip] = row

        for ip, count in counts.items():
            if count >= 3:
                row = first_event[ip]

                self.alerts.append({
                    "rule": "Repeated Failed Logins",
                    "time": row.get("time", ""),
                    "ip": ip,
                    "severity": "HIGH",
                    "snippet": row.get("request", "")[:240],
                    "match": f"{count} failed-login events from this IP"
                })
    # =============================================================
    # ADD RULE
    # =============================================================

    def add_rule(self):

        win = tk.Toplevel(self)

        win.title(
            "Add Threat Rule"
        )

        win.geometry(
            "560x280"
        )

        win.configure(
            bg=self.bg
        )

        fields = {}

        for row_index, label in enumerate(
            (
                "Rule name",
                "Regex pattern",
                "Severity"
            )
        ):

            tk.Label(
                win,
                text=label,
                bg=self.bg,
                fg=self.text
            ).grid(
                row=row_index,
                column=0,
                padx=10,
                pady=10,
                sticky="w"
            )

            if label == "Severity":

                widget = ttk.Combobox(
                    win,
                    values=(
                        "LOW",
                        "MEDIUM",
                        "HIGH",
                        "CRITICAL"
                    ),
                    state="readonly"
                )

                widget.set(
                    "MEDIUM"
                )

            else:

                widget = ttk.Entry(
                    win,
                    width=58
                )

            widget.grid(
                row=row_index,
                column=1,
                padx=10,
                pady=10
            )

            fields[label] = widget

        def save():

            name = fields[
                "Rule name"
            ].get().strip()

            pattern = fields[
                "Regex pattern"
            ].get().strip()

            severity = fields[
                "Severity"
            ].get()

            if not name or not pattern:

                messagebox.showwarning(
                    "Missing data",
                    "Enter rule name and pattern."
                )

                return

            try:

                self.detector.add_rule(
                    name,
                    pattern,
                    severity
                )

            except Exception as e:

                messagebox.showerror(
                    "Invalid rule",
                    str(e)
                )

                return

            win.destroy()

            self.status_var.set(
                f"Added rule: {name}. Run detection again."
            )

        tk.Button(
            win,
            text="SAVE RULE",
            command=save,
            bg="#073c59",
            fg="white",
            relief="flat",
            padx=20,
            pady=8
        ).grid(
            row=3,
            column=1,
            pady=15
        )

    # =============================================================
    # REMOVE RULE
    # =============================================================

    def remove_rule(self):

        names = self.detector.rule_names()

        if not names:
            return

        win = tk.Toplevel(self)

        win.title(
            "Remove Rule"
        )

        win.geometry(
            "460x160"
        )

        win.configure(
            bg=self.bg
        )

        tk.Label(
            win,
            text="Select rule:",
            bg=self.bg,
            fg=self.text
        ).pack(
            pady=10
        )

        box = ttk.Combobox(
            win,
            values=names,
            state="readonly",
            width=50
        )

        box.pack()

        def remove():

            if box.get():

                self.detector.remove_rule(
                    box.get()
                )

                win.destroy()

                self.status_var.set(
                    "Rule removed."
                )

        tk.Button(
            win,
            text="REMOVE",
            command=remove,
            bg="#5a1828",
            fg="white",
            relief="flat",
            padx=20,
            pady=7
        ).pack(
            pady=10
        )

    # =============================================================
    # SHOW RULES
    # =============================================================

    def show_rules(self):

        win = tk.Toplevel(self)

        win.title(
            "Detection Rules"
        )

        win.geometry(
            "900x600"
        )

        tree = ttk.Treeview(
            win,
            columns=(
                "name",
                "severity",
                "pattern"
            ),
            show="headings"
        )

        tree.heading(
            "name",
            text="Rule Name"
        )

        tree.heading(
            "severity",
            text="Severity"
        )

        tree.heading(
            "pattern",
            text="Regular Expression"
        )

        tree.column(
            "name",
            width=230
        )

        tree.column(
            "severity",
            width=100
        )

        tree.column(
            "pattern",
            width=520
        )

        tree.pack(
            fill="both",
            expand=True,
            padx=10,
            pady=10
        )

        for name, rule in self.detector.rules.items():

            tree.insert(
                "",
                "end",
                values=(
                    name,
                    rule["severity"],
                    rule["pattern"]
                )
            )

    # =============================================================
    # DASHBOARD
    # =============================================================

    def show_dashboard(self):

        DashboardWindow(
            self,
            self.rows,
            self.alerts
        )

    # =============================================================
    # THREAT INTELLIGENCE
    # =============================================================

    def show_threat_intel(self):

        win = tk.Toplevel(self)

        win.title(
            "Threat Intelligence / IOC"
        )

        win.geometry(
            "650x430"
        )

        win.configure(
            bg=self.bg
        )

        tk.Label(
            win,
            text="Check an IP against local IOCs and optional online intelligence.",
            bg=self.bg,
            fg=self.text,
            font=("Segoe UI", 10)
        ).pack(
            pady=12
        )

        entry = ttk.Entry(
            win,
            width=42
        )

        entry.pack(
            pady=8
        )

        result = tk.Text(
            win,
            height=14,
            wrap="word",
            bg="#04111d",
            fg=self.text,
            insertbackground=self.text,
            borderwidth=0
        )

        result.pack(
            fill="both",
            expand=True,
            padx=12,
            pady=10
        )

        def check():

            ip = entry.get().strip()

            if ip:

                result.delete(
                    "1.0",
                    "end"
                )

                result.insert(
                    "end",
                    json.dumps(
                        self.intel.lookup_ip(ip),
                        indent=2
                    )
                )

        tk.Button(
            win,
            text="CHECK IP",
            command=check,
            bg="#073c59",
            fg="white",
            relief="flat",
            padx=25,
            pady=8
        ).pack(
            pady=8
        )

    # =============================================================
    # BLOCK LIST
    # =============================================================

    def generate_block_list(self):
        ips = sorted({
            a["ip"]
            for a in self.alerts
            if a.get("severity") in ("HIGH", "CRITICAL")
            and a.get("ip") not in ("N/A", "", None)
        })

        path = Path(__file__).resolve().parent / "blocked_ips.txt"

        try:
            path.write_text(
                "\n".join(ips) + ("\n" if ips else ""),
                encoding="utf-8"
            )

            win = tk.Toplevel(self)
            win.title("Blocked IP Addresses")
            win.geometry("550x420")
            win.configure(bg=self.bg)

            tk.Label(
                win,
                text=f"BLOCKED IP ADDRESSES ({len(ips)})",
                bg=self.bg,
                fg=self.cyan,
                font=("Segoe UI", 14, "bold")
            ).pack(anchor="w", padx=15, pady=(15, 8))

            tk.Label(
                win,
                text="High and Critical severity source IPs",
                bg=self.bg,
                fg=self.muted,
                font=("Segoe UI", 9)
            ).pack(anchor="w", padx=15, pady=(0, 10))

            listing = tk.Listbox(
                win,
                bg=self.panel,
                fg=self.text,
                selectbackground="#123b55",
                font=("Consolas", 11),
                borderwidth=0
            )
            listing.pack(fill="both", expand=True, padx=15, pady=(0, 15))

            if ips:
                for ip in ips:
                    listing.insert(tk.END, ip)
            else:
                listing.insert(tk.END, "No High/Critical IPs to list yet.")

            tk.Label(
                win,
                text="Saved to blocked_ips.txt in the project folder",
                bg=self.bg,
                fg=self.muted,
                font=("Segoe UI", 8)
            ).pack(anchor="w", padx=15, pady=(0, 12))

        except Exception as e:
            messagebox.showerror("Block List Error", str(e))
    # =============================================================
    # CSV
    # =============================================================

    def export_csv(self):

        if not self.alerts:

            messagebox.showwarning(
                "No alerts",
                "Run detection first."
            )

            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[
                ("CSV files", "*.csv")
            ]
        )

        if not path:
            return

        try:

            with open(
                path,
                "w",
                newline="",
                encoding="utf-8"
            ) as file:

                writer = csv.DictWriter(
                    file,
                    fieldnames=[
                        "rule",
                        "time",
                        "ip",
                        "severity",
                        "snippet",
                        "match"
                    ]
                )

                writer.writeheader()

                writer.writerows(
                    self.alerts
                )

            messagebox.showinfo(
                "Exported",
                f"Alerts exported to:\n{path}"
            )

        except Exception as e:

            messagebox.showerror(
                "CSV Error",
                str(e)
            )

    # =============================================================
    # PDF REPORT
    # =============================================================

    def make_report(self):

        if not self.rows:

            messagebox.showwarning(
                "No data",
                "Load logs first."
            )

            return

        if not self.alerts:

            self.run_detection(
                silent=True
            )

        path = filedialog.asksaveasfilename(
            title="Save threat report",
            defaultextension=".pdf",
            filetypes=[
                ("PDF files", "*.pdf")
            ]
        )

        if not path:
            return

        try:

            generate_pdf_report(
                path,
                self.current_file or "Built-in demo logs",
                self.rows,
                self.alerts
            )

            messagebox.showinfo(
                "Report generated",
                f"PDF saved to:\n{path}"
            )

        except Exception as e:

            messagebox.showerror(
                "Report Error",
                str(e)
            )

    # =============================================================
    # START REAL-TIME
    # =============================================================

    def start_realtime(self):

        if not self.current_file:

            messagebox.showinfo(
                "Open Log File First",
                "Real-time watching needs a log file on disk. "
                "Open a .log/.txt file first."
            )

            return

        if self.realtime_running:

            self.status_var.set(
                "Already watching the selected log file."
            )

            return

        try:

            stat = os.stat(
                self.current_file
            )

        except OSError as e:

            messagebox.showerror(
                "Watch Error",
                str(e)
            )

            return

        self.realtime_position = stat.st_size

        self.realtime_file_id = (
            getattr(stat, "st_dev", 0),
            getattr(stat, "st_ino", 0),
        )

        self.realtime_buffer = ""

        self.realtime_running = True

        self.status_var.set(
            f"Watching {Path(self.current_file).name} for new lines."
        )

        self.realtime_thread = threading.Thread(
            target=self._tail_log,
            daemon=True
        )

        self.realtime_thread.start()

    # =============================================================
    # STOP REAL-TIME
    # =============================================================

    def stop_realtime(self):

        self.realtime_running = False

        self.status_var.set(
            "Log watching stopped."
        )

    # =============================================================
    # TAIL LOG
    # =============================================================

    def _tail_log(self):

        while (
            self.realtime_running
            and
            self.current_file
        ):

            try:

                path = self.current_file

                stat = os.stat(
                    path
                )

                current_id = (
                    getattr(stat, "st_dev", 0),
                    getattr(stat, "st_ino", 0),
                )

                # File replacement
                if (
                    self.realtime_file_id
                    != current_id
                ):

                    self.realtime_file_id = current_id
                    self.realtime_position = 0
                    self.realtime_buffer = ""

                # File truncation
                if (
                    stat.st_size
                    <
                    self.realtime_position
                ):

                    self.realtime_position = 0
                    self.realtime_buffer = ""

                # New data
                if (
                    stat.st_size
                    >
                    self.realtime_position
                ):

                    with open(
                        path,
                        "rb"
                    ) as file:

                        file.seek(
                            self.realtime_position
                        )

                        chunk = file.read()

                        self.realtime_position = file.tell()

                    if chunk:

                        text = chunk.decode(
                            "utf-8",
                            errors="replace"
                        )

                        combined = (
                            self.realtime_buffer
                            +
                            text
                        )

                        parts = combined.splitlines(
                            keepends=True
                        )

                        complete_lines = []

                        self.realtime_buffer = ""

                        if parts:

                            if parts[-1].endswith(
                                (
                                    "\n",
                                    "\r"
                                )
                            ):

                                complete_lines = parts

                            else:

                                complete_lines = parts[:-1]

                                self.realtime_buffer = (
                                    parts[-1]
                                )

                        new_rows = []

                        for line in complete_lines:

                            row = parse_log_line(
                                line
                            )

                            if row:

                                new_rows.append(
                                    row
                                )

                        if new_rows:

                            self.after(
                                0,
                                lambda rs=new_rows:
                                self._process_realtime_rows(rs)
                            )

                time.sleep(
                    0.5
                )

            
            
            except (OSError, ValueError) as e:
                self.after(
                    0,
                    lambda err=str(e): messagebox.showerror(
                        "Real-Time Monitoring Error", err
                    )
                )
                time.sleep(0.5)

            except Exception as e:
                self.after(
                    0,
                    lambda err=str(e): messagebox.showerror(
                        "Real-Time Monitoring Error", err
                    )
                )
                time.sleep(0.5)

    # =============================================================
    # PROCESS REAL-TIME ROWS
    # =============================================================

    def _process_realtime_rows(
        self,
        new_rows
    ):

        self.rows.extend(
            new_rows
        )

        new_alerts = []

        for row in new_rows:

            request = row.get(
                "request",
                ""
            )

            if self.normalize_var.get():

                text = normalize_text(
                    request
                )

            else:

                text = request

            matches = self.detector.detect(
                text
            )

            # IOC
            if self.intel.is_malicious_ip(
                row.get("ip", "")
            ):

                matches.append(
                    {
                        "rule":
                            "Threat Intelligence IOC",

                        "severity":
                            "HIGH",

                        "match":
                            f"Known malicious IP: "
                            f'{row.get("ip", "")}'
                    }
                )

            for match in matches:

                alert = {
                    "rule":
                        match["rule"],

                    "time":
                        row.get("time", ""),

                    "ip":
                        row.get("ip", "N/A"),

                    "severity":
                        match["severity"],

                    "snippet":
                        request[:240],

                    "match":
                        match["match"]
                }

                self.alerts.append(
                    alert
                )

                new_alerts.append(
                    alert
                )

                if self.notify_var.get():

                    try:

                        notify(
                            "Real-time threat detected",
                            f'{match["rule"]} '
                            f'from {row.get("ip", "N/A")}'
                        )

                    except Exception:
                        pass

        self._refresh_logs_and_alerts()

        self.status_var.set(
            f"Real-time: "
            f"{len(new_rows)} new line(s), "
            f"{len(new_alerts)} new alert(s)."
        )


# =============================================================
# START APPLICATION
# =============================================================

if __name__ == "__main__":

    app = App()

    app.mainloop()