# -*- coding: utf-8 -*-
"""Orbitals Crash B - targeted E8 first-field writer scanner.
Reads existing x64 COFF .o/.obj files only. No build, setup, or game changes.
"""
import struct, threading, queue, traceback
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

def U16(b, o): return struct.unpack_from("<H", b, o)[0]
def U32(b, o): return struct.unpack_from("<I", b, o)[0]

def coff_text_sections(path):
    b = Path(path).read_bytes()
    if len(b) < 20: raise ValueError("COFF header too short")
    machine, nsec, _, symptr, nsyms, optsz, _ = struct.unpack_from("<HHIIIHH", b, 0)
    if machine != 0x8664: raise ValueError("Not x64 COFF")
    sections = []
    base = 20 + optsz
    for i in range(nsec):
        o = base + i * 40
        if o + 40 > len(b): break
        name = b[o:o+8].split(b"\0", 1)[0].decode("ascii", "replace")
        size, ptr, relptr = U32(b,o+16), U32(b,o+20), U32(b,o+24)
        nrel = U16(b,o+32)
        if name not in (".text", "text", ".text$mn"): continue
        raw = b[ptr:min(ptr+size, len(b))] if ptr < len(b) else b""
        relocs = []
        if relptr and nrel and relptr + nrel*10 <= len(b):
            for j in range(nrel):
                r = relptr + j*10
                relocs.append((U32(b,r), U32(b,r+4), U16(b,r+8)))
        sections.append((name, raw, relocs))
    return sections

def scan_object(path, md):
    hits = []
    for secname, code, relocs in coff_text_sections(path):
        if not code: continue
        insns = list(md.disasm(code, 0))
        tainted = {}  # register -> offset of IMUL * 0xE8
        relmap = [(o, si, typ) for o, si, typ in relocs]
        for i, ins in enumerate(insns):
            m, ops = ins.mnemonic.lower(), ins.operands

            # End taint at clear function/flow boundaries. This deliberately
            # favors precision over trying to emulate the whole CFG.
            if m in ("ret", "retq", "jmp"):
                tainted.clear()
                continue
            if m == "call":
                # Caller-saved x64 registers may be clobbered by the callee.
                for r in ("rax","rcx","rdx","r8","r9","r10","r11","eax","ecx","edx"):
                    tainted.pop(r, None)
                continue

            # IMUL reg, reg, 0xE8 (or decimal 232) creates an E8-derived index.
            if m == "imul" and len(ops) >= 2 and ops[0].type == X86_OP_REG:
                dst = ins.reg_name(ops[0].reg)
                if any(op.type == X86_OP_IMM and op.imm == 0xE8 for op in ops[1:]):
                    tainted[dst] = ins.address
                elif dst in tainted:
                    tainted.pop(dst, None)
                continue

            # MOV register copy propagates the derived address/index.
            if m in ("mov", "movabs") and len(ops) >= 2 and ops[0].type == X86_OP_REG:
                dst = ins.reg_name(ops[0].reg)
                src = ins.reg_name(ops[1].reg) if ops[1].type == X86_OP_REG else None
                if src in tainted: tainted[dst] = tainted[src]
                else: tainted.pop(dst, None)
                continue

            # LEA propagates when its base or index came from the E8 multiply.
            if m == "lea" and len(ops) >= 2 and ops[0].type == X86_OP_REG and ops[1].type == X86_OP_MEM:
                dst = ins.reg_name(ops[0].reg)
                mem = ops[1].mem
                used = [ins.reg_name(x) for x in (mem.base, mem.index) if x]
                origins = [tainted[r] for r in used if r in tainted]
                if origins: tainted[dst] = origins[0]
                else: tainted.pop(dst, None)
                continue

            # A write to a register by another instruction invalidates it.
            if ops and ops[0].type == X86_OP_REG:
                dst = ins.reg_name(ops[0].reg)
                if dst in tainted and m not in ("cmp","test","push","pop"):
                    tainted.pop(dst, None)

            # Keep only stores to [E8-derived address + 0]: likely field +0.
            if not ops or ops[0].type != X86_OP_MEM: continue
            if not (m.startswith("mov") or m in ("xchg","cmpxchg","add","sub","and","or","xor","inc","dec")): continue
            mem = ops[0].mem
            if mem.disp != 0: continue
            regs = [ins.reg_name(x) for x in (mem.base, mem.index) if x]
            used = [r for r in regs if r in tainted]
            if not used: continue
            src = ops[1] if len(ops) > 1 else None
            if src and src.type == X86_OP_REG: srcdesc = ins.reg_name(src.reg)
            elif src and src.type == X86_OP_IMM: srcdesc = hex(src.imm)
            else: srcdesc = "memory/other"
            near = [(o,si,t) for o,si,t in relmap if ins.address-8 <= o <= ins.address+8]
            ctx = insns[max(0,i-6):min(len(insns),i+5)]
            hits.append({
                "path":str(path), "section":secname, "offset":ins.address,
                "ins":f"{ins.mnemonic} {ins.op_str}",
                "base":ins.reg_name(mem.base) if mem.base else "-",
                "index":ins.reg_name(mem.index) if mem.index else "-",
                "origin":"; ".join(f"{r} from IMUL@0x{tainted[r]:X}" for r in used),
                "source":srcdesc,
                "reloc":"; ".join(f"off=0x{o:X} symidx={si} type={t}" for o,si,t in near) or "-",
                "context":"\n".join(f"  {x.address:08X}: {x.mnemonic:<8} {x.op_str}" for x in ctx)
            })
    return hits

class App:
    def __init__(self, root):
        self.root=root; root.title("Orbitals Crash B — E8 ciblé v5"); root.geometry("1260x780")
        self.q=queue.Queue(); self.hits=[]
        bar=ttk.Frame(root,padding=8); bar.pack(fill="x")
        self.folder=tk.StringVar()
        ttk.Label(bar,text="Dossier setup-work\\obj :").pack(side="left")
        ttk.Entry(bar,textvariable=self.folder).pack(side="left",fill="x",expand=True,padx=8)
        ttk.Button(bar,text="Parcourir…",command=self.pick).pack(side="left")
        self.run=ttk.Button(bar,text="Analyser",command=self.start); self.run.pack(side="left",padx=5)
        self.savebtn=ttk.Button(bar,text="Exporter TXT",command=self.save, state="disabled"); self.savebtn.pack(side="left")
        self.status=tk.StringVar(value="Prêt — recherche ciblée des stores [adresse issue de IMUL * 0xE8 + 0].")
        ttk.Label(root,textvariable=self.status,padding=6).pack(fill="x")
        self.pb=ttk.Progressbar(root,mode="determinate"); self.pb.pack(fill="x",padx=10)
        cols=("file","off","ins","addr","origin","reloc")
        self.tree=ttk.Treeview(root,columns=cols,show="headings")
        for c,t,w in [("file","Fichier",280),("off","Offset .text",90),("ins","Instruction",230),("addr","Base / index",140),("origin","Origine E8",220),("reloc","Relocation proche",230)]:
            self.tree.heading(c,text=t); self.tree.column(c,width=w,anchor="w")
        self.tree.pack(fill="both",expand=True,padx=10,pady=6)
        self.tree.bind("<<TreeviewSelect>>",self.detail)
        self.detailbox=tk.Text(root,height=13,wrap="none"); self.detailbox.pack(fill="both",expand=False,padx=10,pady=(0,10))
        self.detailbox.insert("end","Sélectionne un résultat pour afficher le contexte.")
        self.detailbox.configure(state="disabled")
        root.after(120,self.poll)
    def pick(self):
        p=filedialog.askdirectory(title="Choisir setup-work\\obj")
        if p: self.folder.set(p)
    def start(self):
        p=Path(self.folder.get())
        if not p.is_dir():
            messagebox.showerror("Dossier invalide","Sélectionne le dossier setup-work\\obj."); return
        self.tree.delete(*self.tree.get_children()); self.hits=[]; self.savebtn.configure(state="disabled")
        self.run.configure(state="disabled"); self.pb["value"]=0; self.status.set("Préparation…")
        threading.Thread(target=self.worker,args=(p,),daemon=True).start()
    def worker(self,p):
        try:
            md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
            files=sorted(set(p.rglob("*.o")) | set(p.rglob("*.obj")))
            if not files:
                self.q.put(("error","Aucun fichier .o/.obj trouvé. Vérifie le dossier choisi.")); return
            self.q.put(("progress",0,len(files)))
            hits=[]; errors=[]
            for n,f in enumerate(files,1):
                try: hits.extend(scan_object(f,md))
                except Exception as e:
                    if len(errors)<12: errors.append(f"{f.name}: {e}")
                self.q.put(("progress",n,len(files)))
            self.q.put(("done",hits,len(files),errors))
        except Exception as e:
            self.q.put(("error",str(e)+"\n"+traceback.format_exc()))
    def poll(self):
        try:
            while True:
                x=self.q.get_nowait()
                if x[0]=="progress":
                    self.pb["maximum"]=max(1,x[2]); self.pb["value"]=x[1]
                    self.status.set(f"Scan ciblé des objets : {x[1]}/{x[2]}…")
                elif x[0]=="error":
                    self.run.configure(state="normal"); self.status.set("Échec")
                    messagebox.showerror("Analyseur",x[1])
                elif x[0]=="done":
                    _,hits,total,errors=x; self.hits=hits
                    for h in hits:
                        self.tree.insert("","end",values=(Path(h["path"]).name,f"0x{h['offset']:X}",h["ins"],f"{h['base']} / {h['index']}",h["origin"],h["reloc"]))
                    self.run.configure(state="normal")
                    self.savebtn.configure(state="normal" if hits else "disabled")
                    self.status.set(f"Terminé : {total} objets parcourus ; {len(errors)} erreurs ; {len(hits)} candidats ciblés.")
                    if errors:
                        messagebox.showwarning("Objets ignorés","Quelques erreurs (maximum 12 affichées) :\n"+"\n".join(errors))
        except queue.Empty: pass
        self.root.after(120,self.poll)
    def detail(self,event=None):
        sel=self.tree.selection()
        if not sel: return
        h=self.hits[self.tree.index(sel[0])]
        txt=(f"Fichier : {h['path']}\nSection : {h['section']} | offset .text : 0x{h['offset']:X}\n"
             f"Instruction : {h['ins']}\nAdresse : base={h['base']} index={h['index']}\n"
             f"Registre(s) dérivé(s) de IMUL * 0xE8 : {h['origin']}\nSource : {h['source']}\n"
             f"Relocations proches : {h['reloc']}\n\nContexte :\n{h['context']}\n\n"
             "IMPORTANT : candidat heuristique uniquement. Le suivi des registres est local et simplifié ; "
             "les alias mémoire, le flot inter-fonctions et les chemins complexes ne sont pas résolus. "
             "Il faut confirmer que l'adresse correspond bien à un élément de la collection du crash.")
        self.detailbox.configure(state="normal"); self.detailbox.delete("1.0","end")
        self.detailbox.insert("end",txt); self.detailbox.configure(state="disabled")
    def save(self):
        if not self.hits: return
        name=filedialog.asksaveasfilename(defaultextension=".txt",filetypes=[("Rapport texte","*.txt")],initialfile="Orbitals_CrashB_E8_v5.txt")
        if not name: return
        with open(name,"w",encoding="utf-8") as f:
            f.write(f"ORBITALS CRASH B — E8 ciblé v5\nCandidats : {len(self.hits)}\n\n")
            for i,h in enumerate(self.hits,1):
                f.write(f"===== CANDIDAT {i} =====\n")
                for k in ("path","section","offset","ins","base","index","origin","source","reloc","context"):
                    f.write(f"{k}: {h[k]}\n")
                f.write("\n")
        messagebox.showinfo("Export terminé",f"Rapport enregistré :\n{name}")

if __name__=="__main__":
    root=tk.Tk(); App(root); root.mainloop()
