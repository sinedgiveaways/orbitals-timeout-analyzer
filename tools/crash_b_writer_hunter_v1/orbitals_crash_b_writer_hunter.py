# -*- coding: utf-8 -*-
"""Targeted Crash B scanner: six existing COFF objects, E8-stride QWORD stores."""
import struct, threading
from pathlib import Path
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
try:
 from capstone import Cs, CS_ARCH_X86, CS_MODE_64
 from capstone.x86 import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
except Exception as e:
 Cs=None; CAPSTONE_ERROR=str(e)

TARGETS={
 "main_main_0156.o":[0x3795F],
 "main_main_0157.o":[0x7D6A,0x23F0A,0x23F15],
 "main_main_0173.o":[0x2968B,0x2968F,0x29F1C,0x29F44],
 "main_main_0186.o":[0x615A7,0x615CB],
 "main_main_0330.o":[0x17282,0x17291],
 "main_main_0184.o":[0x1952F],
}
def u16(b,o): return struct.unpack_from("<H",b,o)[0]
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def read_text(p):
 b=Path(p).read_bytes()
 if len(b)<20: raise ValueError("COFF header incomplet")
 machine,nsec,_,_,_,optsz,_=struct.unpack_from("<HHIIIHH",b,0)
 if machine!=0x8664: raise ValueError("Objet non x64 COFF")
 out=[]
 for i in range(nsec):
  o=20+optsz+i*40
  if o+40>len(b): break
  name=b[o:o+8].split(b"\0",1)[0].decode("ascii","replace")
  size,ptr=u32(b,o+16),u32(b,o+20)
  if name in (".text","text",".text$mn") and ptr and ptr+size<=len(b): out.append((name,b[ptr:ptr+size]))
 if not out: raise ValueError("Section .text introuvable")
 return out
def scan(code,md):
 ins=list(md.disasm(code,0)); taint={}; hits=[]
 for i,x in enumerate(ins):
  m=x.mnemonic.lower(); op=x.operands
  if m.startswith("ret") or m=="jmp": taint.clear(); continue
  if m=="call":
   for r in ("rax","rcx","rdx","r8","r9","r10","r11","eax","ecx","edx"): taint.pop(r,None)
   continue
  if m=="imul" and len(op)>=3 and op[0].type==X86_OP_REG and op[2].type==X86_OP_IMM and op[2].imm==0xE8:
   taint[x.reg_name(op[0].reg)]=x.address; continue
  if m in ("mov","movabs") and len(op)>=2 and op[0].type==X86_OP_REG:
   d=x.reg_name(op[0].reg); s=x.reg_name(op[1].reg) if op[1].type==X86_OP_REG else None
   if s in taint: taint[d]=taint[s]
   else: taint.pop(d,None)
   continue
  if m=="lea" and len(op)>=2 and op[0].type==X86_OP_REG and op[1].type==X86_OP_MEM:
   d=x.reg_name(op[0].reg); mm=op[1].mem
   src=[x.reg_name(r) for r in (mm.base,mm.index) if r]
   v=[taint[r] for r in src if r in taint]
   if v: taint[d]=v[0]
   else: taint.pop(d,None)
   continue
  if op and op[0].type==X86_OP_REG:
   d=x.reg_name(op[0].reg)
   if d in taint and m not in ("cmp","test","push","pop"): taint.pop(d,None)
  if not op or op[0].type!=X86_OP_MEM or m not in ("mov","movabs","xchg","cmpxchg","add","sub","and","or","xor","inc","dec"): continue
  mm=op[0].mem; regs=[x.reg_name(r) for r in (mm.base,mm.index) if r]
  origins=[(r,taint[r]) for r in regs if r in taint]
  if not origins or op[0].size not in (4,8): continue
  src=op[1] if len(op)>1 else None
  val=x.reg_name(src.reg) if src and src.type==X86_OP_REG else (hex(src.imm & ((1<<(op[0].size*8))-1)) if src and src.type==X86_OP_IMM else "memory/other")
  hits.append((i,x,mm.disp,origins,val,op[0].size))
 return ins,hits
def context(ins,idx,r=20):
 return "\n".join((">> " if j==idx else "   ")+f"{ins[j].address:08X}: {ins[j].mnemonic:<9} {ins[j].op_str}" for j in range(max(0,idx-r),min(len(ins),idx+r+1)))
def report(folder):
 if Cs is None: raise RuntimeError("Capstone absent: "+CAPSTONE_ERROR)
 md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
 out=["ORBITALS CRASH B — E8 QWORD WRITER HUNTER v1","Analyse des six objets existants uniquement. Aucun build, génération ou recompilation.","Offsets en section .text des objets COFF.","="*76]
 for name,anchors in TARGETS.items():
  p=Path(folder)/name; out += ["","#"*76,"FICHIER : "+str(p)]
  if not p.is_file(): out.append("ABSENT — ignoré."); continue
  try:
   allhits=[]
   for sec,code in read_text(p):
    ins,hits=scan(code,md); allhits.append((sec,ins,hits))
    qw=[h for h in hits if h[5]==8]; q0=[h for h in qw if h[2]==0]
    out.append(f"{sec}: stores stride E8={len(hits)}; QWORD={len(qw)}; QWORD displacement 0={len(q0)}")
    out.append("ECRITURES QWORD DETECTEES :")
    if not qw: out.append("  Aucune avec le suivi local.")
    for idx,x,disp,orig,val,size in qw:
     out.append(f"\n{sec}+0x{x.address:X} disp={disp:+#x}: {x.mnemonic} {x.op_str}; origine={orig}; source={val}")
     out.append(context(ins,idx,12))
   out.append("\nCONTEXTES DES 12 SITES FOURNIS :")
   for sec,ins,hits in allhits:
    pos={x.address:i for i,x in enumerate(ins)}
    for a in anchors:
     if a in pos:
      out.append(f"\n--- {sec}+0x{a:X} ---"); out.append(context(ins,pos[a],25))
     else: out.append(f"\n{sec}+0x{a:X}: offset non décodé.")
  except Exception as e: out.append("ERREUR : "+repr(e))
 out += ["","LIMITES : IMUL * 0xE8 est un indice de stride, pas une preuve de type. Le suivi est local et ne résout pas les alias, le flot complet, les appels ni les valeurs runtime.","Un store QWORD à displacement 0 est un candidat d'écriture du premier champ ; il faut encore le relier au consommateur main_main_0184.o+0x1952F."]
 return "\n".join(out)
class App:
 def __init__(self,r):
  self.r=r; r.title("Orbitals Crash B — E8 QWORD Writer Hunter"); r.geometry("780x230"); self.path=tk.StringVar()
  f=ttk.Frame(r,padding=14); f.pack(fill="both",expand=True)
  ttk.Label(f,text="Sélectionne setup-work\\obj :").pack(anchor="w")
  row=ttk.Frame(f); row.pack(fill="x",pady=8)
  ttk.Entry(row,textvariable=self.path).pack(side="left",fill="x",expand=True)
  ttk.Button(row,text="Parcourir",command=self.pick).pack(side="left",padx=5)
  self.status=tk.StringVar(value="Prêt — seuls les 6 objets ciblés seront lus.")
  ttk.Label(f,textvariable=self.status).pack(anchor="w",pady=8)
  self.pb=ttk.Progressbar(f,mode="indeterminate"); self.pb.pack(fill="x")
  self.btn=ttk.Button(f,text="Analyser et créer le rapport TXT",command=self.run); self.btn.pack(anchor="e",pady=12)
 def pick(self):
  p=filedialog.askdirectory()
  if p:self.path.set(p)
 def run(self):
  p=Path(self.path.get())
  if not p.is_dir(): messagebox.showerror("Dossier invalide","Choisis setup-work\\obj."); return
  self.btn.config(state="disabled"); self.pb.start(10); self.status.set("Analyse ciblée en cours…")
  def work():
   try:
    data=report(p); dest=p/"orbitals_crash_b_qword_report.txt"; dest.write_text(data,encoding="utf-8")
    self.r.after(0,lambda:self.done(dest,None))
   except Exception as e:self.r.after(0,lambda:self.done(None,str(e)))
  threading.Thread(target=work,daemon=True).start()
 def done(self,p,e):
  self.pb.stop(); self.btn.config(state="normal")
  if e:self.status.set("Échec"); messagebox.showerror("Erreur",e)
  else:self.status.set("Terminé"); messagebox.showinfo("Rapport créé",str(p)+"\n\nEnvoie-moi le TXT en plusieurs messages.")
if __name__=="__main__":
 if Cs is None:
  root=tk.Tk(); root.withdraw(); messagebox.showerror("Capstone manquant",CAPSTONE_ERROR); raise SystemExit(1)
 root=tk.Tk(); App(root); root.mainloop()
