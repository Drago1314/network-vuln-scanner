"""
dashboard.py — Tkinter GUI for NetVulnScanner
Dark-themed real-time dashboard with live scan output, results table, and export.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import queue
import socket
import subprocess
import os
import sys
import webbrowser
from datetime import datetime

# Ensure parent dir on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scanner.host_scanner import HostScanner, PortScanner
from scanner.vuln_mapper import map_port_to_owasp, SEVERITY_COLOR, calculate_risk_score
from reports.generator import generate_html_report, generate_csv_report

# ─── Color Palette ────────────────────────────────────────────────────────────
BG        = "#0d1117"
BG2       = "#161b22"
BG3       = "#21262d"
BORDER    = "#30363d"
FG        = "#e6edf3"
FG_DIM    = "#8b949e"
ACCENT    = "#58a6ff"
GREEN     = "#3fb950"
ORANGE    = "#f0883e"
RED       = "#FF3B30"
YELLOW    = "#e3b341"
CYAN      = "#5AC8FA"

SEV_COLORS = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
    "INFO":     CYAN,
}

FONT_MONO  = ("Consolas", 10)
FONT_SMALL = ("Segoe UI", 9)
FONT_NORM  = ("Segoe UI", 10)
FONT_BOLD  = ("Segoe UI", 10, "bold")
FONT_H1    = ("Segoe UI", 14, "bold")
FONT_H2    = ("Segoe UI", 11, "bold")


class NetVulnScannerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetVulnScanner — Network Vulnerability Dashboard")
        self.geometry("1280x800")
        self.minsize(1100, 700)
        self.configure(bg=BG)

        self.scan_results = []
        self.log_queue    = queue.Queue()
        self.is_scanning  = False

        self._apply_style()
        self._build_ui()
        self._poll_log_queue()

        # Auto-fill local network
        local_ip = self._get_local_ip()
        if local_ip:
            base = ".".join(local_ip.split(".")[:3])
            self.target_var.set(f"{base}.0/24")

    # ── Styling ───────────────────────────────────────────────────────────────

    def _apply_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure(".", background=BG, foreground=FG, fieldbackground=BG2,
                        troughcolor=BG3, bordercolor=BORDER, darkcolor=BG2,
                        lightcolor=BG3, selectforeground=FG, selectbackground=ACCENT)
        style.configure("TFrame",  background=BG)
        style.configure("TLabel",  background=BG, foreground=FG, font=FONT_NORM)
        style.configure("TEntry",  fieldbackground=BG2, foreground=FG, insertcolor=FG,
                        bordercolor=BORDER, relief="flat")
        style.configure("Accent.TButton", background=ACCENT, foreground=BG,
                        font=FONT_BOLD, relief="flat", padding=(14, 8))
        style.map("Accent.TButton", background=[("active", "#79c0ff"), ("disabled", BG3)])
        style.configure("Danger.TButton", background=RED, foreground=FG,
                        font=FONT_BOLD, relief="flat", padding=(14, 8))
        style.configure("Outline.TButton", background=BG2, foreground=FG_DIM,
                        font=FONT_NORM, relief="flat", padding=(12, 6),
                        borderwidth=1, bordercolor=BORDER)
        style.map("Outline.TButton", background=[("active", BG3)])
        style.configure("TCombobox", fieldbackground=BG2, foreground=FG,
                        selectforeground=FG, selectbackground=BG2)
        style.configure("Treeview", background=BG2, fieldbackground=BG2,
                        foreground=FG, rowheight=30, borderwidth=0, font=FONT_SMALL)
        style.configure("Treeview.Heading", background=BG3, foreground=FG_DIM,
                        font=("Segoe UI", 9, "bold"), borderwidth=0)
        style.map("Treeview", background=[("selected", BG3)], foreground=[("selected", FG)])
        style.configure("TProgressbar", troughcolor=BG3, background=ACCENT, borderwidth=0)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG3, foreground=FG_DIM,
                        padding=(16, 8), font=FONT_NORM)
        style.map("TNotebook.Tab", background=[("selected", BG2)], foreground=[("selected", FG)])

    # ── UI Layout ─────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Header ──
        header = tk.Frame(self, bg=BG2, height=64, highlightthickness=1, highlightbackground=BORDER)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)

        tk.Label(header, text="🛡️  NetVulnScanner", font=("Segoe UI", 15, "bold"),
                 bg=BG2, fg=ACCENT).pack(side="left", padx=20, pady=16)
        tk.Label(header, text="Network Vulnerability Dashboard", font=FONT_SMALL,
                 bg=BG2, fg=FG_DIM).pack(side="left")

        self.status_dot = tk.Label(header, text="●  Idle", font=FONT_SMALL, bg=BG2, fg=FG_DIM)
        self.status_dot.pack(side="right", padx=20)

        # ── Control Bar ──
        ctrl = tk.Frame(self, bg=BG, pady=12)
        ctrl.pack(fill="x", padx=20)

        tk.Label(ctrl, text="Target:", bg=BG, fg=FG_DIM, font=FONT_SMALL).grid(row=0, column=0, padx=(0,6))
        self.target_var = tk.StringVar(value="192.168.1.0/24")
        target_entry = tk.Entry(ctrl, textvariable=self.target_var, bg=BG2, fg=FG, font=FONT_MONO,
                                relief="flat", insertbackground=FG, highlightthickness=1,
                                highlightbackground=BORDER, highlightcolor=ACCENT, width=22)
        target_entry.grid(row=0, column=1, padx=(0,16), ipady=6)

        tk.Label(ctrl, text="Profile:", bg=BG, fg=FG_DIM, font=FONT_SMALL).grid(row=0, column=2, padx=(0,6))
        self.profile_var = tk.StringVar(value="standard")
        profile_cb = ttk.Combobox(ctrl, textvariable=self.profile_var, width=14, state="readonly",
                                  values=["quick", "standard", "full", "vuln", "stealth"])
        profile_cb.grid(row=0, column=3, padx=(0,16))

        tk.Label(ctrl, text="Scan Mode:", bg=BG, fg=FG_DIM, font=FONT_SMALL).grid(row=0, column=4, padx=(0,6))
        self.scan_mode_var = tk.StringVar(value="Full Scan")
        mode_cb = ttk.Combobox(ctrl, textvariable=self.scan_mode_var, width=14, state="readonly",
                               values=["Full Scan", "Single Host", "Port Range"])
        mode_cb.grid(row=0, column=5, padx=(0,20))

        self.scan_btn = ttk.Button(ctrl, text="▶  Start Scan", style="Accent.TButton",
                                   command=self._start_scan)
        self.scan_btn.grid(row=0, column=6, padx=(0,8))

        self.stop_btn = ttk.Button(ctrl, text="■  Stop", style="Danger.TButton",
                                   command=self._stop_scan, state="disabled")
        self.stop_btn.grid(row=0, column=7, padx=(0,8))

        ttk.Button(ctrl, text="Export HTML", style="Outline.TButton",
                   command=self._export_html).grid(row=0, column=8, padx=(0,6))
        ttk.Button(ctrl, text="Export CSV", style="Outline.TButton",
                   command=self._export_csv).grid(row=0, column=9, padx=(0,6))
        ttk.Button(ctrl, text="🗑 Clear", style="Outline.TButton",
                   command=self._clear_results).grid(row=0, column=10)

        # ── Progress ──
        prog_frame = tk.Frame(self, bg=BG)
        prog_frame.pack(fill="x", padx=20, pady=(0, 10))
        self.progress_var = tk.IntVar(value=0)
        self.progress_bar = ttk.Progressbar(prog_frame, variable=self.progress_var,
                                            maximum=100, mode="determinate")
        self.progress_bar.pack(fill="x")

        # ── Main Paned ──
        paned = tk.PanedWindow(self, orient="horizontal", bg=BORDER, sashwidth=3, sashrelief="flat")
        paned.pack(fill="both", expand=True, padx=20, pady=(0, 12))

        # Left: Results Table
        left_frame = tk.Frame(paned, bg=BG)
        paned.add(left_frame, minsize=600)
        self._build_results_panel(left_frame)

        # Right: Log + Detail
        right_frame = tk.Frame(paned, bg=BG)
        paned.add(right_frame, minsize=320)
        self._build_right_panel(right_frame)

    def _build_results_panel(self, parent):
        tk.Label(parent, text="Scan Results", font=FONT_H2, bg=BG, fg=FG).pack(anchor="w", pady=(0, 8))

        # Summary bar
        self.summary_frame = tk.Frame(parent, bg=BG)
        self.summary_frame.pack(fill="x", pady=(0, 10))
        self._build_summary_bar()

        # Treeview
        cols = ("Host", "Port", "Service", "Severity", "OWASP", "Title")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")
        widths = [110, 60, 100, 80, 80, 260]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col, command=lambda c=col: self._sort_tree(c))
            self.tree.column(col, width=w, minwidth=50)

        # Tags for severity colors
        for sev, color in SEV_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

    def _build_summary_bar(self):
        for w in self.summary_frame.winfo_children():
            w.destroy()

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for host in self.scan_results:
            for f in host.get("findings", []):
                counts[f.get("severity", "INFO")] += 1

        total = sum(counts.values())
        tk.Label(self.summary_frame, text=f"Findings: {total}", font=FONT_BOLD,
                 bg=BG, fg=FG).pack(side="left", padx=(0, 16))

        SEV_BG = {"CRITICAL": "#3d1210", "HIGH": "#3d2310", "MEDIUM": "#3a2e10", "LOW": "#102e14", "INFO": "#103240"}
        for sev, cnt in counts.items():
            badge = tk.Label(self.summary_frame,
                             text=f" {sev} {cnt} ",
                             font=("Segoe UI", 8, "bold"),
                             bg=SEV_BG.get(sev, BG3),
                             fg=SEV_COLORS[sev],
                             padx=6, pady=2, relief="flat")
            badge.pack(side="left", padx=2)

    def _build_right_panel(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True)

        # Tab 1: Live Log
        log_frame = ttk.Frame(nb)
        nb.add(log_frame, text="📟  Live Log")
        self.log_text = tk.Text(log_frame, bg=BG2, fg=FG_DIM, font=FONT_MONO,
                                relief="flat", state="disabled", wrap="word",
                                insertbackground=FG, selectbackground=BG3)
        log_sb = ttk.Scrollbar(log_frame, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)
        log_sb.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True, padx=8, pady=8)

        # Color tags for log
        self.log_text.tag_configure("INFO",     foreground=CYAN)
        self.log_text.tag_configure("SUCCESS",  foreground=GREEN)
        self.log_text.tag_configure("WARNING",  foreground=YELLOW)
        self.log_text.tag_configure("ERROR",    foreground=RED)
        self.log_text.tag_configure("CRITICAL", foreground=RED)
        self.log_text.tag_configure("DIM",      foreground=FG_DIM)

        # Tab 2: Finding Detail
        detail_frame = ttk.Frame(nb)
        nb.add(detail_frame, text="🔍  Finding Detail")
        self.detail_text = tk.Text(detail_frame, bg=BG2, fg=FG, font=FONT_SMALL,
                                   relief="flat", state="disabled", wrap="word",
                                   padx=12, pady=12)
        detail_sb = ttk.Scrollbar(detail_frame, command=self.detail_text.yview)
        self.detail_text.configure(yscrollcommand=detail_sb.set)
        detail_sb.pack(side="right", fill="y")
        self.detail_text.pack(fill="both", expand=True)

        # Tab 3: Risk Summary
        risk_frame = ttk.Frame(nb)
        nb.add(risk_frame, text="📊  Risk Summary")
        self.risk_canvas = tk.Canvas(risk_frame, bg=BG2, highlightthickness=0)
        self.risk_canvas.pack(fill="both", expand=True)

    # ── Scanning Logic ────────────────────────────────────────────────────────

    def _start_scan(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Input Error", "Please enter a target IP or range.")
            return

        self.is_scanning = True
        self.scan_results = []
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_dot.config(text="●  Scanning...", fg=GREEN)
        self._clear_tree()
        self.progress_var.set(0)
        self._log_msg(f"Starting scan → Target: {target}", "INFO")

        t = threading.Thread(target=self._run_scan, args=(target,), daemon=True)
        t.start()

    def _stop_scan(self):
        self.is_scanning = False
        self._log_msg("Scan stopped by user.", "WARNING")
        self._scan_finished()

    def _run_scan(self, target: str):
        try:
            host_scanner = HostScanner(log_callback=self._log_msg)
            port_scanner = PortScanner(log_callback=self._log_msg)
            profile = self.profile_var.get()

            self._log_msg("Phase 1/3: Host Discovery ...", "INFO")

            # Determine if single host or range
            if "/" in target or "-" in target:
                hosts = host_scanner.arp_scan(target)
            else:
                hostname = HostScanner._resolve_hostname(target)
                hosts = [{"ip": target, "mac": "N/A", "hostname": hostname}]

            if not hosts:
                self._log_msg("No live hosts found.", "WARNING")
                self.after(0, self._scan_finished)
                return

            self._log_msg(f"Phase 2/3: Port Scanning {len(hosts)} host(s) ...", "INFO")

            for i, host in enumerate(hosts):
                if not self.is_scanning:
                    break
                ip = host["ip"]
                self._log_msg(f"Scanning ports on {ip} ...", "DIM")
                result = port_scanner.scan_host(ip, profile=profile)
                result["hostname"] = host.get("hostname", "Unknown")
                result["mac"]      = host.get("mac", "N/A")

                # Map to OWASP
                findings = []
                for port_data in result.get("ports", []):
                    owasp = map_port_to_owasp(port_data["port"], port_data.get("service", ""))
                    finding = {**port_data, **owasp}
                    findings.append(finding)
                    self.after(0, self._add_tree_row, ip, finding)

                result["findings"] = findings
                self.scan_results.append(result)

                progress = int(((i + 1) / len(hosts)) * 80)
                self.after(0, self.progress_var.set, progress)

            self._log_msg("Phase 3/3: Generating risk assessment ...", "INFO")
            all_findings = [f for h in self.scan_results for f in h.get("findings", [])]
            risk = calculate_risk_score(all_findings)
            self._log_msg(
                f"Scan complete — Risk Grade: {risk['grade']} | Score: {risk['score']}/100 | {risk['label']}",
                "SUCCESS"
            )
            self.after(0, self.progress_var.set, 100)
            self.after(0, self._build_summary_bar)
            self.after(0, self._draw_risk_chart)

        except Exception as e:
            self._log_msg(f"Scan error: {e}", "ERROR")
        finally:
            self.after(0, self._scan_finished)

    def _scan_finished(self):
        self.is_scanning = False
        self.scan_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_dot.config(text=f"●  Idle — {len(self.scan_results)} host(s) scanned", fg=FG_DIM)

    # ── Tree Management ───────────────────────────────────────────────────────

    def _add_tree_row(self, ip: str, finding: dict):
        sev = finding.get("severity", "INFO")
        self.tree.insert("", "end", values=(
            ip,
            f"{finding['port']}/{finding.get('protocol','tcp')}",
            finding.get("service", "—"),
            sev,
            " ".join(finding.get("owasp", [])),
            finding.get("title", "—"),
        ), tags=(sev,))

    def _clear_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def _sort_tree(self, col):
        data = [(self.tree.set(child, col), child) for child in self.tree.get_children("")]
        data.sort()
        for idx, (_, child) in enumerate(data):
            self.tree.move(child, "", idx)

    def _on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        vals = self.tree.item(sel[0], "values")
        if not vals:
            return
        ip, port_str, service, sev, owasp, title = vals
        port = int(port_str.split("/")[0])

        # Find matching finding
        for host in self.scan_results:
            if host["ip"] == ip:
                for f in host.get("findings", []):
                    if f["port"] == port:
                        self._show_detail(host, f)
                        return

    def _show_detail(self, host: dict, finding: dict):
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        color = SEV_COLORS.get(finding.get("severity", "INFO"), FG)
        self.detail_text.tag_configure("title",  font=("Segoe UI", 12, "bold"), foreground=color)
        self.detail_text.tag_configure("label",  font=("Segoe UI", 9, "bold"),  foreground=FG_DIM)
        self.detail_text.tag_configure("value",  font=("Segoe UI", 10),         foreground=FG)
        self.detail_text.tag_configure("green",  foreground=GREEN)
        self.detail_text.tag_configure("red",    foreground=RED)
        self.detail_text.tag_configure("cyan",   foreground=CYAN)

        t = self.detail_text
        t.insert("end", f"{finding.get('title','')}\n\n", "title")

        for label, val in [
            ("Host", f"{host['ip']} ({host.get('hostname','N/A')})"),
            ("Port", f"{finding['port']}/{finding.get('protocol','tcp')}"),
            ("Service", finding.get("service", "—")),
            ("Version", finding.get("version", "N/A")),
            ("Severity", finding.get("severity", "—")),
            ("OS Guess", host.get("os_guess", "N/A")),
        ]:
            t.insert("end", f"{label}:  ", "label")
            t.insert("end", f"{val}\n", "value")

        t.insert("end", "\nDescription\n", "label")
        t.insert("end", f"{finding.get('description', '—')}\n\n", "value")

        t.insert("end", "OWASP Categories\n", "label")
        for o in finding.get("owasp_names", finding.get("owasp", [])):
            t.insert("end", f"  • {o}\n", "cyan")

        cves = finding.get("cve_refs", [])
        if cves:
            t.insert("end", "\nCVE References\n", "label")
            for cve in cves:
                t.insert("end", f"  • {cve}\n", "red")

        t.insert("end", "\n✅ Remediation\n", "label")
        t.insert("end", f"{finding.get('remediation', '—')}\n", "green")

        self.detail_text.config(state="disabled")

    # ── Risk Chart ────────────────────────────────────────────────────────────

    def _draw_risk_chart(self):
        c = self.risk_canvas
        c.delete("all")
        w, h = c.winfo_width() or 320, c.winfo_height() or 400

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for host in self.scan_results:
            for f in host.get("findings", []):
                counts[f.get("severity", "INFO")] += 1

        total = sum(counts.values())
        if total == 0:
            c.create_text(w//2, h//2, text="No findings", fill=FG_DIM, font=FONT_H2)
            return

        all_findings = [f for host in self.scan_results for f in host.get("findings", [])]
        risk = calculate_risk_score(all_findings)

        # Risk score ring
        cx, cy, r = w//2, 100, 70
        start = -90
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = counts[sev]
            if cnt == 0:
                continue
            extent = (cnt / total) * 359.9
            c.create_arc(cx-r, cy-r, cx+r, cy+r, start=start, extent=extent,
                         outline=SEV_COLORS[sev], width=14, style="arc")
            start += extent

        grade_colors = {"A": GREEN, "B": ACCENT, "C": YELLOW, "D": ORANGE, "F": RED}
        gc = grade_colors.get(risk["grade"], FG_DIM)
        c.create_text(cx, cy, text=risk["grade"], fill=gc, font=("Segoe UI", 28, "bold"))
        c.create_text(cx, cy+22, text=risk["label"], fill=FG_DIM, font=("Segoe UI", 8))

        # Bar chart
        bar_x, bar_y, bar_w = 20, 200, w - 40
        c.create_text(bar_x, bar_y - 16, text="Findings by Severity", fill=FG_DIM,
                      font=("Segoe UI", 9, "bold"), anchor="w")

        for i, sev in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]):
            y = bar_y + i * 36
            cnt = counts[sev]
            bar_len = int((cnt / max(total, 1)) * (bar_w - 80))
            color = SEV_COLORS[sev]
            # Label
            c.create_text(bar_x, y + 8, text=sev, fill=color,
                          font=("Consolas", 8, "bold"), anchor="w")
            # Bar
            bx = bar_x + 72
            c.create_rectangle(bx, y, bx + max(bar_len, 4), y + 16,
                                fill=color, outline=color)
            # Count
            c.create_text(bx + bar_len + 8, y + 8, text=str(cnt), fill=color,
                          font=("Segoe UI", 9, "bold"), anchor="w")

        # Score text
        c.create_text(w//2, h - 30,
                      text=f"Risk Score: {risk['score']}/100",
                      fill=gc, font=("Segoe UI", 10, "bold"))

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log_msg(self, msg: str, level: str = "DIM"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_queue.put((f"[{ts}] {msg}\n", level))

    def _poll_log_queue(self):
        try:
            while True:
                msg, level = self.log_queue.get_nowait()
                self.log_text.config(state="normal")
                self.log_text.insert("end", msg, level)
                self.log_text.see("end")
                self.log_text.config(state="disabled")
        except queue.Empty:
            pass
        self.after(100, self._poll_log_queue)

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_html(self):
        if not self.scan_results:
            messagebox.showwarning("No Data", "Run a scan first.")
            return
        path = generate_html_report(self.scan_results)
        if messagebox.askyesno("Export Done", f"HTML report saved:\n{path}\n\nOpen in browser?"):
            webbrowser.open(f"file://{os.path.abspath(path)}")

    def _export_csv(self):
        if not self.scan_results:
            messagebox.showwarning("No Data", "Run a scan first.")
            return
        path = generate_csv_report(self.scan_results)
        messagebox.showinfo("Export Done", f"CSV report saved:\n{path}")

    def _clear_results(self):
        self.scan_results = []
        self._clear_tree()
        self.progress_var.set(0)
        self._build_summary_bar()
        self.risk_canvas.delete("all")
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.config(state="disabled")
        self.status_dot.config(text="●  Idle", fg=FG_DIM)

    # ── Utility ───────────────────────────────────────────────────────────────

    @staticmethod
    def _get_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return ""


def run():
    app = NetVulnScannerApp()
    app.mainloop()


if __name__ == "__main__":
    run()
