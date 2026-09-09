"""Item 4 (final): disjoint-split generalisation on the paper's frozen dataset,
global normalisation/encoding as in preprocess.py. Splits: random, session-disjoint,
source(IP)-disjoint. Prints metrics, writes a summary CSV, and generates the
publication figure ml-pipeline/results/fig_generalisation.png. Reads raw log only."""
import re, os
from urllib.parse import unquote_plus
from collections import deque
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, f1_score
from catboost import CatBoostClassifier

RAW="traffic-generator/dataset/traffic_logs.csv"; RES="ml-pipeline/results"; W=10.0
CANON={"normal","sql_injection","brute_force","bola","api_flooding",
       "credential_stuffing","parameter_tampering","token_replay"}
SQLK=["select","union","drop","or ","'","--","#","=",";","sleep"]
def nep(p): return re.sub(r"/\d+","/{id}",str(p))
def tgt(p):
    m=re.match(r"/users/(\d+)",str(p)); return m.group(1) if m else None
def bf(b):
    x=unquote_plus(str(b)).lower()
    return len(x),sum(x.count(c) for c in ["'",'"',";","-","=","#","(",")"]),sum(1 for k in SQLK if k in x)
def nf(t):
    s=unquote_plus(str(t)); v=[]
    for z in re.findall(r"-?\d+\.?\d*",s):
        try:v.append(float(z))
        except:pass
    return (max(v) if v else 0.0),(min(v) if v else 0.0),(1 if any(q<0 for q in v) else 0),s.count(":")

def build():
    df=pd.read_csv(RAW).drop_duplicates()
    df["timestamp"]=pd.to_datetime(df["timestamp"],errors="coerce",utc=True)
    df=df.dropna(subset=["timestamp"])
    df=df[df["label"].isin(CANON)]
    df=df[df["timestamp"]<pd.Timestamp("2026-09-01",tz="UTC")]     # paper-frozen (Aug 17)
    df=df.sort_values("timestamp").reset_index(drop=True)
    df["endpoint_norm"]=df["endpoint"].apply(nep); df["hour"]=df["timestamp"].dt.hour
    df["is_error"]=(df["status_code"]>=400).astype(int); df["is_login"]=(df["endpoint"]=="/login").astype(int)
    df["target_user"]=df["endpoint"].apply(tgt)
    bl,bs,bh,mx,mn,ng,fc=[],[],[],[],[],[],[]
    for b in df["request_body"]:
        l,s,h=bf(b); a,c,d,e=nf(b); bl.append(l);bs.append(s);bh.append(h);mx.append(a);mn.append(c);ng.append(d);fc.append(e)
    df["body_len"],df["body_special"],df["body_sql_hits"]=bl,bs,bh
    df["body_max_num"],df["body_min_num"],df["body_has_neg"],df["body_field_count"]=mx,mn,ng,fc
    n=len(df); ts=df["timestamp"].astype("int64").to_numpy()/1e9
    ips=df["ip_address"].to_numpy(); er=df["is_error"].to_numpy(); lo=df["is_login"].to_numpy()
    ep=df["endpoint_norm"].to_numpy(); tu=df["target_user"].to_numpy()
    a1=np.zeros(n);a2=np.zeros(n);a3=np.zeros(n);a4=np.zeros(n);a5=np.zeros(n);st={}
    for i in range(n):
        dq=st.setdefault(ips[i],deque()); dq.append((ts[i],er[i],lo[i],ep[i],tu[i]))
        while dq and ts[i]-dq[0][0]>W: dq.popleft()
        a1[i]=len(dq);a2[i]=sum(x[1] for x in dq);a3[i]=sum(x[2] for x in dq)
        a4[i]=len(set(x[3] for x in dq));a5[i]=len(set(x[4] for x in dq if x[4] is not None))
    df["ip_req_10s"],df["ip_fail_10s"]=a1,a2; df["ip_fail_ratio_10s"]=a2/np.maximum(a1,1)
    df["ip_login_10s"],df["ip_uniq_ep_10s"],df["ip_distinct_users_10s"]=a3,a4,a5
    tok=np.zeros(n);stt={};uid=df["user_id"].astype(str).to_numpy()
    for i in range(n):
        u=uid[i]
        if u in ("anon","invalid_token","none","nan"): tok[i]=0; continue
        tq=stt.setdefault(u,deque()); tq.append((ts[i],ips[i]))
        while tq and ts[i]-tq[0][0]>W: tq.popleft()
        tok[i]=len(set(x[1] for x in tq))
    df["token_ips_10s"]=tok
    return df

NUM=["status_code","response_time_ms","request_size","response_size","hour","body_len",
 "body_special","body_sql_hits","body_max_num","body_min_num","body_has_neg","body_field_count",
 "is_error","is_login","ip_req_10s","ip_fail_10s","ip_fail_ratio_10s","ip_login_10s",
 "ip_uniq_ep_10s","ip_distinct_users_10s","token_ips_10s"]
CAT=["method","endpoint_norm","country","device"]

def run(name,df,FEAT,tr,te):
    Xtr,Xte=df[FEAT].iloc[tr],df[FEAT].iloc[te]
    ytr,yte=df["label"].astype(str).iloc[tr],df["label"].astype(str).iloc[te]
    m=CatBoostClassifier(iterations=400,depth=8,learning_rate=0.1,loss_function="MultiClass",
                         auto_class_weights="Balanced",random_seed=42,verbose=False)
    m.fit(Xtr,ytr); p=m.predict(Xte).ravel().astype(str); yv=yte.values
    acc=accuracy_score(yv,p); mf1=f1_score(yv,p,average="macro")
    rep=classification_report(yv,p,zero_division=0,output_dict=True)
    mask=(yv=="normal"); fpr=float((p[mask]!="normal").mean()) if mask.sum() else float("nan")
    print(f"\n=== {name} ===")
    print(f"train={len(tr)} test={len(te)} | accuracy={acc:.3f} macro-F1={mf1:.3f} normal-FPR={fpr:.3f}")
    for cls in sorted(k for k in rep if k not in ("accuracy","macro avg","weighted avg")):
        print(f"  {cls:22s} F1={rep[cls]['f1-score']:.3f} recall={rep[cls]['recall']:.3f} n={int(rep[cls]['support'])}")
    return name,acc,mf1,fpr

def figure(rows):
    os.makedirs(RES,exist_ok=True)
    labels=["Random\n(reference)","Session-\ndisjoint","Source-disjoint\n(unseen IPs)"]
    mf1=[r[2] for r in rows]; fpr=[r[3] for r in rows]
    x=np.arange(3); w=0.36
    fig,ax=plt.subplots(figsize=(6.4,3.8))
    b1=ax.bar(x-w/2,mf1,w,label="Macro-F1",color="#3B6FB6",edgecolor="black",linewidth=0.6)
    b2=ax.bar(x+w/2,fpr,w,label="Normal false-positive rate",color="#D1894B",edgecolor="black",linewidth=0.6)
    ax.set_ylim(0,1.12); ax.set_ylabel("Score"); ax.set_xticks(x); ax.set_xticklabels(labels)
    for bars in (b1,b2):
        for b in bars:
            ax.text(b.get_x()+b.get_width()/2,b.get_height()+0.015,f"{b.get_height():.3f}",
                    ha="center",va="bottom",fontsize=9)
    ax.legend(loc="lower center",bbox_to_anchor=(0.5,1.0),ncol=2,frameon=False,fontsize=9)
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    plt.tight_layout(); plt.savefig(os.path.join(RES,"fig_generalisation.png"),dpi=300,bbox_inches="tight")
    print("\nfigure saved:",os.path.join(RES,"fig_generalisation.png"))

def main():
    df=build()
    df[NUM]=df[NUM].fillna(0); df[NUM]=StandardScaler().fit_transform(df[NUM])
    for c in CAT: df[c+"_enc"]=LabelEncoder().fit_transform(df[c].astype(str))
    FEAT=NUM+[c+"_enc" for c in CAT]; n=len(df); y=df["label"].astype(str).values
    print("rows:",n," IPs:",df["ip_address"].nunique()," sessions:",df["session_id"].nunique())
    idx=np.arange(n); gss=GroupShuffleSplit(n_splits=1,test_size=0.2,random_state=42)
    tr,te=train_test_split(idx,test_size=0.2,random_state=42,stratify=y)
    r1=run("Random 80/20 (reference)",df,FEAT,tr,te)
    tr,te=next(gss.split(idx,groups=df["session_id"].values)); r2=run("Session-disjoint",df,FEAT,tr,te)
    tr,te=next(gss.split(idx,groups=df["ip_address"].values)); r3=run("Source-disjoint (unseen IPs)",df,FEAT,tr,te)
    rows=[r1,r2,r3]
    pd.DataFrame([{"split":a,"accuracy":b,"macro_f1":c,"normal_fpr":d} for a,b,c,d in rows]
                ).to_csv(os.path.join(RES,"generalisation_summary.csv"),index=False)
    figure(rows)
    print("\n===== SUMMARY =====")
    for a,b,c,d in rows: print(f"{a:34s} acc={b:.3f} macroF1={c:.3f} FPR={d:.3f}")

if __name__=="__main__":
    main()
