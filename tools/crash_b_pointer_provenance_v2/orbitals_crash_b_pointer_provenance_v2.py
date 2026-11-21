# -*- coding: utf-8 -*-
"""Crash B focused dataflow inspector for main_main_0184.o. No game build steps."""
import struct, threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
except Exception as e:
    Cs = None
    CAPSTONE_ERROR = str(e)

TARGET = "main_main_0184.o"
FAULT = 0x1952F
WINDOW = 0x90

def u32(b, o): return struct.unpack_from("<I", b, o)[0]

def read_text(path):
    b = Path(path).read_bytes()
    if len(b) < 20: raise ValueError("En-tête COFF incomplet")
    machine, nsec, _, _, _, optsz, _ = struct.unpack_from("<HHIIIHH", b, 0)
    if machine != 0x8664: raise ValueError("Objet COFF x64 attendu")
    sections = []
    for i in range(nsec):
        o = 20 + optsz + i * 40
        if o + 40 > len(b): break
        name = b[o:o+8].split(b"\0", 1)[0].decode("ascii", "replace")
        size, ptr = u32(b, o+16), u32(b, o+20)
        if name in (".text", "text", ".text$mn") and ptr and ptr+size <= len(b):
            sections.append((name, b[ptr:ptr+size]))
    if not sections: raise ValueError("Section .text introuvable")
    return sections

def regname(ins, reg): return ins.reg_name(reg) if reg else ""

def mem_desc(ins, op):
    m = op.mem
    return (regname(ins,m.base), regname(ins,m.index), m.scale, m.disp)

def fmt_ins(ins, mark=False):
    return (" >> " if mark else "    ") + f"{ins.address:08X}: {ins.mnemonic:<9} {ins.op_str}"

def disassemble(code):
    md = Cs(CS_ARCH_X86, CS_MODE_64); md.detail = True
    return list(md.disasm(code, 0))

def analyze(code):
    ins = disassemble(code)
    byaddr = {x.address:i for i,x in enumerate(ins)}
    lines = [
        "ORBITALS CRASH B — FOCUSED POINTER PROVENANCE v2",
        "Objet analysé : main_main_0184.o / section .text",
        f"Instruction cible : +0x{FAULT:X}",
        "Lecture seule des objets existants. Aucun prepare.py/build/génération/recompilation.",
        "="*88, ""
    ]
    if FAULT not in byaddr:
        lines += [f"ERREUR : offset 0x{FAULT:X} non décodé dans .text.", "Taille .text : "+hex(len(code))]
        return "\n".join(lines)

    # Locate the containing function approximately using nearby returns and unconditional jumps.
    fi = byaddr[FAULT]
    lo = max(0, fi-500); hi = min(len(ins), fi+500)
    # Report all exact [rsi+0xd8] memory operands in the local neighborhood and globally.
    d8 = []
    for i,x in enumerate(ins):
        for oi,op in enumerate(x.operands):
            if op.type == X86_OP_MEM:
                b,idx,scale,disp = mem_desc(x,op)
                if b == "rsi" and idx == "" and disp == 0xD8:
                    d8.append((i,x,oi,op))
    lines += ["[1] ACCÈS À [RSI+0xD8] DANS TOUTE LA SECTION .text", f"Occurrences : {len(d8)}"]
    if not d8: lines.append("Aucun accès direct trouvé (possible alias/spill ou base différente).")
    for i,x,oi,op in d8:
        lines.append(f"\n{fmt_ins(x)} | taille={op.size} | operand={oi}")
        lines += [fmt_ins(ins[j], j==i) for j in range(max(0,i-8),min(len(ins),i+10))]

    # A deliberately conservative, local register provenance pass around the fault.
    # Track: RAX <- [RSI+D8], RCX <- [RAX], register copies/LEAs; invalidate at calls.
    tracked = {}  # register -> provenance label
    events = []
    for i,x in enumerate(ins):
        m=x.mnemonic.lower(); ops=x.operands
        if m.startswith("ret") or m in ("jmp","call"):
            if m=="call":
                for r in ("rax","rcx","rdx","r8","r9","r10","r11"):
                    tracked.pop(r,None)
            elif m=="jmp":
                tracked.clear()
            continue
        if len(ops)>=2 and ops[0].type==X86_OP_REG:
            dst=regname(x,ops[0].reg)
            src=ops[1]
            if src.type==X86_OP_MEM:
                b,idx,scale,disp=mem_desc(x,src)
                if b=="rsi" and not idx and disp==0xD8:
                    tracked[dst]="PTR_FROM_RSI_D8"
                    events.append((i,"load-slot",dst,x))
                elif b in tracked and not idx and disp==0:
                    tracked[dst]=tracked[b]+" -> FIRST_QWORD"
                    events.append((i,"load-first-qword",dst,x))
                else:
                    tracked.pop(dst,None)
            elif src.type==X86_OP_REG:
                sr=regname(x,src.reg)
                if sr in tracked: tracked[dst]=tracked[sr]
                else: tracked.pop(dst,None)
            elif m=="lea" and src.type==X86_OP_MEM:
                b,idx,scale,disp=mem_desc(x,src)
                if b in tracked and not idx:
                    tracked[dst]=tracked[b]+f" + {disp:+#x}"
                else: tracked.pop(dst,None)
            else:
                tracked.pop(dst,None)

        # Any memory write whose base is a register known as the first-QWORD table base.
        if ops and ops[0].type==X86_OP_MEM and len(ops)>=2:
            b,idx,scale,disp=mem_desc(x,ops[0])
            if b in tracked and "FIRST_QWORD" in tracked[b]:
                events.append((i,"write-through-derived-base",tracked[b],x))
            elif b in tracked and tracked[b]=="PTR_FROM_RSI_D8":
                events.append((i,"write-through-slot-pointer",tracked[b],x))

    lines += ["", "[2] CHAÎNE DE PROVENANCE LOCALE AUTOUR DE L'ACCÈS FAUTIF",
              "Suivi heuristique des MOV/LEA simples ; les appels et branches rendent le suivi incomplet."]
    for i in range(max(0,fi-70),min(len(ins),fi+35)):
        x=ins[i]
        tag=""
        if i==fi: tag="  <<< INSTRUCTION FAUTIVE"
        lines.append(fmt_ins(x, i==fi)+tag)
    lines += ["", "[3] ÉVÉNEMENTS DE PROVENANCE DÉTECTÉS DANS .text", f"Nombre : {len(events)}"]
    for i,kind,prov,x in events:
        lines.append(f"\n{kind} | provenance={prov}")
        lines.append(fmt_ins(x))
        lines += [fmt_ins(ins[j],j==i) for j in range(max(0,i-5),min(len(ins),i+7))]
    # All writes at [reg+0] and QWORD writes, useful for finding a first-field initializer.
    lines += ["", "[4] ÉCRITURES QWORD À DÉPLACEMENT 0 (CANDIDATS, NON ATTRIBUÉS SANS PROVENANCE)"]
    count=0
    for i,x in enumerate(ins):
        if not x.operands or x.operands[0].type!=X86_OP_MEM: continue
        op=x.operands[0]
        if op.size==8:
            b,idx,scale,disp=mem_desc(x,op)
            if disp==0 and b and not idx and x.mnemonic.lower() in ("mov","movabs","xchg","cmpxchg"):
                count+=1
                lines.append(fmt_ins(x))
                lines += [fmt_ins(ins[j],j==i) for j in range(max(0,i-3),min(len(ins),i+4))]
    if not count: lines.append("Aucun store QWORD [registre] direct trouvé.")
    lines += ["", "[5] BRANCHES ET APPELS DANS LA FENÊTRE DE LA CIBLE"]
    for i in range(max(0,fi-WINDOW),min(len(ins),fi+WINDOW)):
        x=ins[i]
        if x.mnemonic.lower().startswith("j") or x.mnemonic.lower()=="call":
            lines.append(fmt_ins(x))
    lines += ["", "[6] CONCLUSION / LIMITES",
              "- Un accès direct [rsi+0xD8] n'identifie pas à lui seul le propriétaire de l'objet.",
              "- Le premier QWORD est lu par la séquence [rsi+0xD8] -> [rax] -> rcx.",
              "- Les écritures candidates doivent être reliées au même objet ; le déplacement 0 seul ne prouve rien.",
              "- Le suivi est linéaire et local : il ne résout pas les chemins CFG, alias, spills, interprocédural ou valeurs runtime.",
              "- L'accès fautif observé utilise un index (2-edx)*0x38 et un champ +0x5C ; ce n'est pas un stride 0xE8."]
    return "\n".join(lines)

def make_report(folder):
    if Cs is None: raise RuntimeError("Capstone manquant : "+CAPSTONE_ERROR)
    p=Path(folder)/TARGET
    if not p.is_file(): raise FileNotFoundError(f"{TARGET} introuvable dans {folder}")
    out=[]
    for name,code in read_text(p):
        out.append(analyze(code))
    dest=Path(folder)/"orbitals_crash_b_pointer_provenance_v2.txt"
    dest.write_text("\n\n".join(out),encoding="utf-8")
    return dest

class App:
    def __init__(self,root):
        self.root=root; root.title("Orbitals Crash B — Pointer Provenance v2"); root.geometry("780x240")
        self.path=tk.StringVar()
        f=ttk.Frame(root,padding=14); f.pack(fill="both",expand=True)
        ttk.Label(f,text="Dossier setup-work\\obj (contient main_main_0184.o) :").pack(anchor="w")
        row=ttk.Frame(f); row.pack(fill="x",pady=8)
        ttk.Entry(row,textvariable=self.path).pack(side="left",fill="x",expand=True)
        ttk.Button(row,text="Parcourir",command=self.pick).pack(side="left",padx=5)
        self.status=tk.StringVar(value="Prêt — analyse du seul main_main_0184.o.")
        ttk.Label(f,textvariable=self.status).pack(anchor="w",pady=8)
        self.pb=ttk.Progressbar(f,mode="indeterminate"); self.pb.pack(fill="x")
        self.btn=ttk.Button(f,text="Analyser et créer le rapport TXT",command=self.run); self.btn.pack(anchor="e",pady=12)
    def pick(self):
        p=filedialog.askdirectory()
        if p:self.path.set(p)
    def run(self):
        p=Path(self.path.get())
        if not p.is_dir(): messagebox.showerror("Dossier invalide","Sélectionne setup-work\\obj."); return
        self.btn.config(state="disabled"); self.pb.start(10); self.status.set("Analyse ciblée en cours…")
        def work():
            try:
                dest=make_report(p)
                self.root.after(0,lambda:self.done(dest,None))
            except Exception as e:
                err=str(e); self.root.after(0,lambda:self.done(None,err))
        threading.Thread(target=work,daemon=True).start()
    def done(self,p,e):
        self.pb.stop(); self.btn.config(state="normal")
        if e:self.status.set("Échec"); messagebox.showerror("Erreur",e)
        else:self.status.set("Terminé"); messagebox.showinfo("Rapport créé",str(p)+"\n\nEnvoie-moi ce fichier TXT.")
if __name__=="__main__":
    if Cs is None:
        root=tk.Tk(); root.withdraw(); messagebox.showerror("Capstone manquant",CAPSTONE_ERROR); raise SystemExit(1)
    root=tk.Tk(); App(root); root.mainloop()
