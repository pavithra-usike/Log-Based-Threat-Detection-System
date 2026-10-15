import tkinter as tk
def notify(title,message):
    try:
        root=tk._default_root
        if root: root.after(0,lambda:_toast(root,title,message))
    except Exception: pass
def _toast(root,title,message):
    w=tk.Toplevel(root); w.title(title); w.attributes("-topmost",True); w.geometry("360x115")
    tk.Label(w,text=title,font=("Segoe UI",11,"bold")).pack(pady=(12,3))
    tk.Label(w,text=message,wraplength=330).pack()
    tk.Button(w,text="Close",command=w.destroy).pack(pady=5)
    w.after(3500,lambda:w.destroy() if w.winfo_exists() else None)
