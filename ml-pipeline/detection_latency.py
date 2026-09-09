"""Item 6: session/event-level operational metrics.
Out-of-fold (5-fold) CatBoost predictions on the frozen 8-class dataset; then,
per attack episode (grouped by session_id), measures requests-passed-before-first
detection, time-to-first-detection, and share caught on the first request.
Detection = classifier predicts non-normal. Writes CSV + figure. Reads raw log."""
import re, os
from urllib.parse import unquote_plus
from collections import deque
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
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

def main():
    df=build()
    for c in ["method","endpoint_norm","country","device"]:
        df[c+"_enc"]=LabelEncoder().fit_transform(df[c].astype(str))
    FEAT=NUM+["method_enc","endpoint_norm_enc","country_enc","device_enc"]
    y=df["label"].astype(str).to_numpy(dtype=object); n=len(df)
    oof=np.empty(n,dtype=object)
    for tr,te in StratifiedKFold(5,shuffle=True,random_state=42).split(np.arange(n),y):
        m=CatBoostClassifier(iterations=400,depth=8,learning_rate=0.1,loss_function="MultiClass",
                             auto_class_weights="Balanced",random_seed=42,verbose=False)
        m.fit(df[FEAT].iloc[tr],y[tr]); oof[te]=m.predict(df[FEAT].iloc[te]).ravel().astype(str)
    df["pred"]=oof; df["detected"]=(df["pred"]!="normal")
    ATT=sorted(c for c in CANON if c!="normal")
    rows=[]
    for cls in ATT:
        sub=df[df["label"]==cls]
        n_ep=0; det_ep=0; reqs=[]; times=[]; first=0
        req_recall=sub["detected"].mean()
        for sid,g in sub.groupby("session_id"):
            g=g.sort_values("timestamp"); d=g["detected"].values; t=g["timestamp"].values
            n_ep+=1
            if d.any():
                k=int(np.argmax(d)); det_ep+=1; reqs.append(k)
                times.append((pd.Timestamp(t[k])-pd.Timestamp(t[0])).total_seconds())
                if k==0: first+=1
        rows.append({"attack":cls,"episodes":n_ep,"request_recall":round(req_recall,3),
                     "episode_detect_rate":round(det_ep/n_ep,3) if n_ep else 0,
                     "median_reqs_before_block":int(np.median(reqs)) if reqs else -1,
                     "median_time_to_detect_s":round(float(np.median(times)),2) if times else -1,
                     "caught_on_first_req_pct":round(first/n_ep,3) if n_ep else 0})
    res=pd.DataFrame(rows); print(res.to_string(index=False))
    os.makedirs(RES,exist_ok=True); res.to_csv(os.path.join(RES,"detection_latency.csv"),index=False)
    # figure: median requests passed before first block, per attack class
    fig,ax=plt.subplots(figsize=(6.8,3.8))
    vals=[r["median_reqs_before_block"] for r in rows]; labs=[r["attack"].replace("_","\n") for r in rows]
    ax.bar(np.arange(len(rows)),vals,color="#3B6FB6",edgecolor="black",linewidth=0.6)
    for i,v in enumerate(vals): ax.text(i,v+0.03,str(v),ha="center",va="bottom",fontsize=9)
    ax.set_xticks(np.arange(len(rows))); ax.set_xticklabels(labs,fontsize=8)
    ax.set_ylabel("Median requests before first block")
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    plt.tight_layout(); plt.savefig(os.path.join(RES,"fig_detection_latency.png"),dpi=300,bbox_inches="tight")
    print("\nsaved:",os.path.join(RES,"detection_latency.csv"),"and fig_detection_latency.png")

if __name__=="__main__":
    main()
