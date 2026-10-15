import tkinter as tk
from tkinter import ttk
from collections import Counter
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
class DashboardWindow(tk.Toplevel):
    def __init__(self,parent,rows,alerts):
        super().__init__(parent); self.title("Security Dashboard"); self.geometry("1150x760"); self.rows=rows; self.alerts=alerts; self._build()
    def _build(self):
        cards=ttk.Frame(self,padding=10); cards.pack(fill="x")
        vals=[("Total Logs",len(self.rows)),("Total Alerts",len(self.alerts)),("High/Critical",sum(a["severity"] in ("HIGH","CRITICAL") for a in self.alerts)),("Unique IPs",len({r["ip"] for r in self.rows if r["ip"]!="N/A"}))]
        for title,val in vals:
            f=ttk.LabelFrame(cards,text=title,padding=16); f.pack(side="left",fill="x",expand=True,padx=5); ttk.Label(f,text=str(val),font=("Segoe UI",20,"bold")).pack()
        fig=Figure(figsize=(10.5,5.8),dpi=100); ax=fig.add_subplot(111); c=Counter(a["rule"] for a in self.alerts)
        if c:
            ax.barh(list(c.keys()),list(c.values())); ax.set_title("Threats by Rule"); ax.set_xlabel("Alerts"); fig.tight_layout()
        else: ax.text(.5,.5,"No alerts to visualize yet.",ha="center",va="center",transform=ax.transAxes); ax.set_axis_off()
        canvas=FigureCanvasTkAgg(fig,master=self); canvas.draw(); canvas.get_tk_widget().pack(fill="both",expand=True,padx=10,pady=10)
        sev=Counter(a["severity"] for a in self.alerts)
        ttk.Label(self,text="Severity: "+", ".join(f"{k}={v}" for k,v in sev.items()) or "No alerts",padding=10).pack(anchor="w")
