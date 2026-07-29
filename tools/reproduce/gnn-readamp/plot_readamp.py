import json, re
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

BG="#0b0d12"; SURF="#12161f"; TXT="#c7d0db"; MUT="#7e8a99"
RED="#f87171"; GRN="#4ade80"; GRID="#1f2733"

def parse_phase(path):
    t0=None; prog=[]
    for ln in open(path):
        if ln.startswith("PHASE_START"): t0=int(re.search(r"mono_ns=(\d+)",ln).group(1))
        elif ln.startswith("PROGRESS"):
            prog.append((int(re.search(r"mono_ns=(\d+)",ln).group(1)),
                         int(re.search(r"signal_bytes=(\d+)",ln).group(1)),
                         int(re.search(r"store_bytes=(\d+)",ln).group(1))))
    return t0,prog

def reads(path,t0):
    ts=[];slba=[];byt=[]
    for ln in open(path):
        try:r=json.loads(ln)
        except:continue
        if r.get("event_type")=="nvme_cmd" and r.get("op_name")=="read" and int(r["ts"])>=t0:
            ts.append(int(r["ts"]));slba.append(int(r["slba"]));byt.append(int(r["bytes"]))
    return np.array(ts),np.array(slba,dtype=np.int64),np.array(byt)

arms=[("NeighborLoader  (naive neighbor sampling)","/tmp/ssd_nbr_nat.jsonl","/tmp/ssd_nbr_nat.phase.txt",RED,430.9),
      ("Page-Aware  (knlp read-amp fix)","/tmp/ssd_page_nat.jsonl","/tmp/ssd_page_nat.phase.txt",GRN,8.6)]

plt.rcParams.update({"figure.facecolor":BG,"axes.facecolor":SURF,"savefig.facecolor":BG,
    "text.color":TXT,"axes.labelcolor":TXT,"xtick.color":MUT,"ytick.color":MUT,
    "axes.edgecolor":GRID,"font.size":11})
fig,axs=plt.subplots(2,2,figsize=(14,9))
fig.suptitle("Read amplification of a GNN reading node features from an SSD\n"
             "DGraphFin financial-fraud graph (3.7M nodes) - Samsung 9100 PRO Gen5 - captured with eBPF (nvme_tp_monitor)",
             color="#e8eef5",fontsize=15,y=0.99)

data=[]; maxMB=0; maxspanMB=0
for name,cap,ph,col,ra in arms:
    t0,prog=parse_phase(ph); ts,slba,byt=reads(cap,t0)
    rel=(ts-t0)/1e9; cumMB=np.cumsum(byt)/1e6
    pr=np.array(prog,dtype=float); prel=(pr[:,0]-t0)/1e9; usefulMB=pr[:,1]/1e6
    base=slba.min(); offMB=(slba-base)*512/1e6
    data.append((name,col,ra,rel,cumMB,offMB,prel,usefulMB))
    maxMB=max(maxMB,cumMB[-1]); maxspanMB=max(maxspanMB,offMB.max())

for i,(name,col,ra,rel,cumMB,offMB,prel,usefulMB) in enumerate(data):
    ax=axs[0][i]
    ax.plot(rel,cumMB,color=col,lw=2.4,label="device MB read (SSD mechanism, eBPF)")
    ax.plot(prel,usefulMB,color=TXT,lw=1.8,ls="--",label="useful MB (what the GNN consumes)")
    ax.fill_between(rel,cumMB,np.interp(rel,prel,usefulMB),color=col,alpha=0.12)
    ax.set_ylim(0,maxMB*1.06); ax.set_xlim(0,max(rel))
    ax.set_title(name,color="#e8eef5",fontsize=12.5,pad=8)
    ax.set_ylabel("cumulative MB"); ax.grid(True,color=GRID,lw=0.6)
    ax.legend(loc="upper left",fontsize=9,facecolor=SURF,edgecolor=GRID,labelcolor=TXT)
    ax.text(0.97,0.5,f"{ra:.0f}x\nread\namp",transform=ax.transAxes,ha="right",va="center",
            color=col,fontsize=30,fontweight="bold",alpha=0.9)
    ax2=axs[1][i]
    n=len(offMB); step=max(1,n//7000)
    ax2.scatter(rel[::step],offMB[::step],s=3,color=col,alpha=0.30,edgecolors="none")
    ax2.set_ylim(0,maxspanMB*1.03); ax2.set_xlim(0,max(rel))
    ax2.set_xlabel("time (s)"); ax2.set_ylabel("offset into store file (MB)")
    ax2.set_title(f"access pattern: every dot is one 4K device read  ({n:,} reads)",color=MUT,fontsize=10.5)
    ax2.grid(True,color=GRID,lw=0.6)

fig.text(0.5,0.012,"Same data, same SSD. The only change is the access pattern - a knlp architectural fix - yet the naive path reads ~50x more from the device for the same GNN signal.",
         ha="center",color=MUT,fontsize=10.5)
plt.tight_layout(rect=[0,0.025,1,0.955])
plt.savefig("/tmp/gnn_readamp_ab.png",dpi=130)
print("wrote; file MB span:",round(maxspanMB,1))
