# -*- coding: utf-8 -*-
import struct, threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM

OBJ = "main_main_0184.o"
TARGETS = [0x18F5C, 0x18F71, 0x1943A, 0x19473, 0x194A4, 0x19507, 0x1952F]

def parse_coff(path):
    b = Path(path).read_bytes()
    if len(b) < 20: raise ValueError("COFF trop court")
    machine, nsec, _, _, symptr, nsyms, opt, _ = struct.unpack_from("<HHIIIHH", b)
    if machine != 0x8664: raise ValueError(f"Machine 0x{machine:04X}, x64 attendu (0x8664)")
    secs = {}
    for i in range(nsec):
        o = 20 + opt + i*40
        name = b[o:o+8].split(b"\0",1)[0].decode("ascii","replace")
        size, ptr = struct.unpack_from("<II", b, o+16)
        if ptr and size and ptr+size <= len(b): secs[name] = b[ptr:ptr+size]
    code = secs.get(".text")
    if code is None: raise ValueError("Section .text absente")
    pdata = secs.get(".pdata", b"")
    funcs=[]
    for o in range(0, len(pdata)-11, 12):
        a,z,u=struct.unpack_from("<III",pdata,o)
        if a < z <= len(code): funcs.append((a,z,u))
    return b,code,funcs,nsec,nsyms

def analyze(path):
    raw, code, funcs, nsec, nsyms = parse_coff(path)
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True; md.skipdata=True
    ins=list(md.disasm(code,0))
    owners={}
    for t in TARGETS:
        owners[t]=next((f for f in funcs if f[0] <= t < f[1]),None)
    selected=[]
    for f in owners.values():
        if f and f not in selected: selected.append(f)
    out=[
      "ORBITALS CRASH B - RAPPORT DE DESASSEMBLAGE",
      f"Objet: {path}", f"Taille fichier: {len(raw):,} octets",
      f"Section .text: 0x{len(code):X} | .pdata fonctions: {len(funcs)} | symboles COFF: {nsyms} | sections: {nsec}",
      "Analyse en lecture seule. Aucun lancement de setup.py/prepare.py, aucune regeneration du jeu.",
      "Offsets exprimes relativement au debut de .text.", "="*88, "",
      "1) FONCTION CONTENANT CHAQUE OFFSET"
    ]
    for t,f in owners.items():
        out.append(f"+0x{t:X}: "+(f"fonction +0x{f[0]:X}..+0x{f[1]:X}, taille 0x{f[1]-f[0]:X}, unwind +0x{f[2]:X}" if f else "pas de plage .pdata"))
    byaddr={x.address:x for x in ins}
    out += ["","2) DESASSEMBLAGE COMPLET DES FONCTIONS CIBLES"]
    for a,z,u in selected:
        out += ["",f"--- fonction +0x{a:X}..+0x{z:X} ---"]
        for x in ins:
            if a<=x.address<z:
                mark=" >>>" if x.address in TARGETS else ""
                out.append(f"{mark} {x.address:08X}: {x.mnemonic:<9} {x.op_str}")
        out += ["","BRANCHES/APPELS DIRECTS :"]
        for x in ins:
            if a<=x.address<z and (x.mnemonic.lower().startswith("j") or x.mnemonic.lower() in ("call","loop","loope","loopne")):
                dest=None
                if x.operands and x.operands[-1].type==X86_OP_IMM: dest=x.operands[-1].imm & 0xffffffffffffffff
                out.append(f"{x.address:08X}: {x.mnemonic} {x.op_str}"+(f" -> +0x{dest:X}" if dest is not None else " [indirect]"))
    out += ["","3) FENETRES LOCALES"]
    for t in TARGETS:
        out += ["",f"--- +0x{t:X}, fenetre +/-0x60 ---"]
        for x in ins:
            if max(0,t-0x60)<=x.address<=t+0x60:
                mark=" >>>" if x.address==t else ""
                out.append(f"{mark} {x.address:08X}: {x.mnemonic:<9} {x.op_str}")
    out += ["","4) OCTETS BRUTS AUTOUR DES ENTREES"]
    for t in TARGETS:
        lo=max(0,t-0x30); hi=min(len(code),t+0x70)
        out.append(f"+0x{lo:X}..+0x{hi:X}: {code[lo:hi].hex(' ')}")
    out += ["","5) LIMITES","- Les sauts indirects et les valeurs runtime ne sont pas resolus.",
            "- Ce rapport ne modifie pas l'executable du jeu et ne pretend pas prouver la cause runtime.",
            "- Il fournit le CFG statique et les instructions exactes pour preparer le correctif Crash B."]
    return "\n".join(out)

class GUI:
 def __init__(self,root):
    self.root=root; root.title("Orbitals - Generateur du rapport Crash B"); root.geometry("720x230")
    self.folder=tk.StringVar()
    f=ttk.Frame(root,padding=16); f.pack(fill="both",expand=True)
    ttk.Label(f,text="Dossier contenant main_main_0184.o (normalement setup-work\\obj)").pack(anchor="w")
    r=ttk.Frame(f); r.pack(fill="x",pady=10)
    ttk.Entry(r,textvariable=self.folder).pack(side="left",fill="x",expand=True)
    ttk.Button(r,text="Parcourir",command=self.pick).pack(side="left",padx=8)
    self.status=tk.StringVar(value="Pret - analyse locale, sans recompilation du jeu.")
    ttk.Label(f,textvariable=self.status).pack(anchor="w",pady=6)
    self.pb=ttk.Progressbar(f,mode="indeterminate"); self.pb.pack(fill="x")
    self.btn=ttk.Button(f,text="Generer le rapport",command=self.run); self.btn.pack(anchor="e",pady=12)
 def pick(self):
    p=filedialog.askdirectory()
    if p:self.folder.set(p)
 def run(self):
    p=Path(self.folder.get())/OBJ
    if not p.is_file():
      messagebox.showerror("Fichier manquant",f"Je ne trouve pas:\n{p}\n\nChoisis le dossier setup-work\\obj."); return
    self.btn.config(state="disabled"); self.pb.start(10); self.status.set("Analyse du desassemblage...")
    def work():
      try:
        report=analyze(p); dest=p.parent/"ORBITALS_CRASH_B_RAPPORT.txt"; dest.write_text(report,encoding="utf-8")
        self.root.after(0,lambda:self.done(dest,None))
      except Exception as e:
        msg=str(e); self.root.after(0,lambda:self.done(None,msg))
    threading.Thread(target=work,daemon=True).start()
 def done(self,dest,err):
    self.pb.stop(); self.btn.config(state="normal")
    if err:self.status.set("Echec"); messagebox.showerror("Erreur",err)
    else:self.status.set("Rapport cree"); messagebox.showinfo("Termine",f"Rapport cree:\n{dest}\n\nEnvoie-moi ce fichier texte ou colle son contenu.")
if __name__=="__main__":
 root=tk.Tk(); GUI(root); root.mainloop()
