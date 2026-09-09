"""Item 7: behavioural baseline vs full model, tested at the SESSION level.
5-fold out-of-fold predictions for a full-feature model and a behavioural-only
baseline; then (a) Wilcoxon signed-rank on per-session accuracy and (b) a
session-clustered bootstrap 95% CI of the macro-F1 difference. Writes CSV+figure."""
import re, os
from urllib.parse import unquote_plus
from collections import deque
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy.stats import wilcoxon
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score
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
    df=df.dropna(subset=["timestamp"]); df=df[df["label"].isin(CANON)]
    df=df[df["timestamp"]<pd.Timestamp("2026-09-01",tz="UTC")]
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
CATENC=["method_enc","endpoint_norm_enc","country_enc","device_enc"]
BEH=[c for c in NUM if c.startswith("ip_") or c.startswith("token_")]

def oof(df,feats,y,n):
    o=np.empty(n,dtype=object)
    for tr,te in StratifiedKFold(5,shuffle=True,random_state=42).split(np.arange(n),y):
        m=CatBoostClassifier(iterations=400,depth=8,learning_rate=0.1,loss_function="MultiClass",
                             auto_class_weights="Balanced",random_seed=42,verbose=False)
        m.fit(df[feats].iloc[tr],y[tr]); o[te]=m.predict(df[feats].iloc[te]).ravel().astype(str)
    return o

def main():
    df=build()
    for c in ["method","endpoint_norm","country","device"]:
        df[c+"_enc"]=LabelEncoder().fit_transform(df[c].astype(str))
    y=df["label"].astype(str).to_numpy(dtype=object); n=len(df)
    FULL=NUM+CATENC
    pf=oof(df,FULL,y,n); pb=oof(df,BEH,y,n)
    f1_full=f1_score(y,pf,average="macro"); f1_beh=f1_score(y,pb,average="macro")
    df["ok_full"]=(pf==y).astype(int); df["ok_beh"]=(pb==y).astype(int); df["sid"]=df["session_id"]
    # (a) per-session accuracy, Wilcoxon signed-rank
    per=df.groupby("sid").agg(full=("ok_full","mean"),beh=("ok_beh","mean"))
    diff=per["full"]-per["beh"]; nz=diff[diff!=0]
    stat,p=wilcoxon(per["full"],per["beh"]) if len(nz)>0 else (float("nan"),1.0)
    # (b) session-clustered bootstrap of macro-F1 difference
    sids=df["sid"].to_numpy(); groups={s:np.where(sids==s)[0] for s in per.index}
    keys=list(groups.keys()); rng=np.random.default_rng(42); deltas=[]
    yv=y
    for _ in range(2000):
        samp=rng.choice(keys,size=len(keys),replace=True)
        idx=np.concatenate([groups[s] for s in samp])
        deltas.append(f1_score(yv[idx],pf[idx],average="macro")-f1_score(yv[idx],pb[idx],average="macro"))
    lo,hi=np.percentile(deltas,[2.5,97.5]); med=np.median(deltas)
    print(f"macro-F1 full={f1_full:.4f}  behavioural-only={f1_beh:.4f}  diff={f1_full-f1_beh:.4f}")
    print(f"sessions={len(per)}  median per-session acc: full={per['full'].median():.3f} beh={per['beh'].median():.3f}")
    print(f"(a) Wilcoxon signed-rank (per-session accuracy): W={stat:.1f}  p={p:.3e}")
    print(f"(b) session-clustered bootstrap dMacroF1: {med:.4f}  95% CI [{lo:.4f}, {hi:.4f}]")
    os.makedirs(RES,exist_ok=True)
    pd.DataFrame([{"f1_full":f1_full,"f1_beh":f1_beh,"f1_diff":f1_full-f1_beh,"sessions":len(per),
                   "wilcoxon_W":stat,"wilcoxon_p":p,"boot_dF1_median":med,"boot_ci_low":lo,"boot_ci_high":hi}
                 ]).to_csv(os.path.join(RES,"session_level_test.csv"),index=False)
    fig,ax=plt.subplots(figsize=(6.4,3.6))
    ax.hist(deltas,bins=40,color="#3B6FB6",edgecolor="white")
    ax.axvline(lo,color="black",ls="--",lw=1); ax.axvline(hi,color="black",ls="--",lw=1); ax.axvline(0,color="red",lw=1)
    ax.set_xlabel("Macro-F1 difference (full - behavioural-only), session-clustered bootstrap")
    ax.set_ylabel("Frequency"); ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    plt.tight_layout(); plt.savefig(os.path.join(RES,"fig_session_test.png"),dpi=300,bbox_inches="tight")
    print("saved: session_level_test.csv and fig_session_test.png")

if __name__=="__main__":
    main()
