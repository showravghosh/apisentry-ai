"""Item 5: distinct-account (credential-diversity) feature + 5-fold ablation.
Adds ip_distinct_logins_10s = distinct usernames attempted per source in 10s,
then compares CatBoost WITHOUT vs WITH it over 5-fold CV, focusing on
brute_force vs credential_stuffing. Frozen 8-class dataset. Writes CSV + figure.
Offline ablation; does not modify the deployed tool."""
import re, os
from urllib.parse import unquote_plus
from collections import deque
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import f1_score, classification_report
from catboost import CatBoostClassifier

RAW="traffic-generator/dataset/traffic_logs.csv"; RES="ml-pipeline/results"; W=10.0
CANON={"normal","sql_injection","brute_force","bola","api_flooding",
       "credential_stuffing","parameter_tampering","token_replay"}
SQLK=["select","union","drop","or ","'","--","#","=",";","sleep"]
def nep(p): return re.sub(r"/\d+","/{id}",str(p))
def tgt(p):
    m=re.match(r"/users/(\d+)",str(p)); return m.group(1) if m else None
def uname(b):
    m=re.search(r'"username"\s*:\s*"([^"]*)"',str(b)); return m.group(1) if m else None
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
    df=df[df["timestamp"]<pd.Timestamp("2026-09-01",tz="UTC")]
    df=df.sort_values("timestamp").reset_index(drop=True)
    df["endpoint_norm"]=df["endpoint"].apply(nep); df["hour"]=df["timestamp"].dt.hour
    df["is_error"]=(df["status_code"]>=400).astype(int); df["is_login"]=(df["endpoint"]=="/login").astype(int)
    df["target_user"]=df["endpoint"].apply(tgt); df["login_user"]=df["request_body"].apply(uname)
    bl,bs,bh,mx,mn,ng,fc=[],[],[],[],[],[],[]
    for b in df["request_body"]:
        l,s,h=bf(b); a,c,d,e=nf(b); bl.append(l);bs.append(s);bh.append(h);mx.append(a);mn.append(c);ng.append(d);fc.append(e)
    df["body_len"],df["body_special"],df["body_sql_hits"]=bl,bs,bh
    df["body_max_num"],df["body_min_num"],df["body_has_neg"],df["body_field_count"]=mx,mn,ng,fc
    n=len(df); ts=df["timestamp"].astype("int64").to_numpy()/1e9
    ips=df["ip_address"].to_numpy(); er=df["is_error"].to_numpy(); lo=df["is_login"].to_numpy()
    ep=df["endpoint_norm"].to_numpy(); tu=df["target_user"].to_numpy(); lu=df["login_user"].to_numpy()
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
    dl=np.zeros(n);stl={}                       # NEW: distinct login usernames per source in 10s
    for i in range(n):
        dq=stl.setdefault(ips[i],deque())
        if lo[i] and lu[i] is not None and str(lu[i])!="nan": dq.append((ts[i],str(lu[i])))
        while dq and ts[i]-dq[0][0]>W: dq.popleft()
        dl[i]=len(set(x[1] for x in dq))
    df["ip_distinct_logins_10s"]=dl
    return df

BASE=["status_code","response_time_ms","request_size","response_size","hour","body_len",
 "body_special","body_sql_hits","body_max_num","body_min_num","body_has_neg","body_field_count",
 "is_error","is_login","ip_req_10s","ip_fail_10s","ip_fail_ratio_10s","ip_login_10s",
 "ip_uniq_ep_10s","ip_distinct_users_10s","token_ips_10s"]
CAT=["method_enc","endpoint_norm_enc","country_enc","device_enc"]
NEW="ip_distinct_logins_10s"

def cv(df,feats,y):
    skf=StratifiedKFold(5,shuffle=True,random_state=42)
    M={"macro_f1":[],"normal_fpr":[],"brute_force_f1":[],"brute_force_rec":[],
       "cred_stuff_f1":[],"cred_stuff_rec":[]}
    for tr,te in skf.split(np.arange(len(df)),y):
        m=CatBoostClassifier(iterations=400,depth=8,learning_rate=0.1,loss_function="MultiClass",
                             auto_class_weights="Balanced",random_seed=42,verbose=False)
        m.fit(df[feats].iloc[tr],y[tr]); p=m.predict(df[feats].iloc[te]).ravel().astype(str); yv=y[te]
        M["macro_f1"].append(f1_score(yv,p,average="macro"))
        r=classification_report(yv,p,zero_division=0,output_dict=True)
        M["brute_force_f1"].append(r.get("brute_force",{}).get("f1-score",0))
        M["brute_force_rec"].append(r.get("brute_force",{}).get("recall",0))
        M["cred_stuff_f1"].append(r.get("credential_stuffing",{}).get("f1-score",0))
        M["cred_stuff_rec"].append(r.get("credential_stuffing",{}).get("recall",0))
        mask=(yv=="normal"); M["normal_fpr"].append(float((p[mask]!="normal").mean()) if mask.sum() else 0)
    return {k:(np.mean(v),np.std(v)) for k,v in M.items()}

def figure(a,b):
    os.makedirs(RES,exist_ok=True)
    keys=["brute_force_f1","cred_stuff_f1","macro_f1"]; labs=["Brute-force F1","Cred-stuffing F1","Macro-F1"]
    am=[a[k][0] for k in keys]; asd=[a[k][1] for k in keys]
    bm=[b[k][0] for k in keys]; bsd=[b[k][1] for k in keys]
    x=np.arange(3); w=0.36
    fig,ax=plt.subplots(figsize=(6.4,3.8))
    ax.bar(x-w/2,am,w,yerr=asd,capsize=3,label="Without distinct-account feature",color="#9AA7B4",edgecolor="black",linewidth=0.6)
    ax.bar(x+w/2,bm,w,yerr=bsd,capsize=3,label="With distinct-account feature",color="#3B6FB6",edgecolor="black",linewidth=0.6)
    ax.set_ylim(0,1.12); ax.set_ylabel("Score"); ax.set_xticks(x); ax.set_xticklabels(labs)
    for i in range(3):
        ax.text(x[i]-w/2,am[i]+asd[i]+0.02,f"{am[i]:.3f}",ha="center",fontsize=8)
        ax.text(x[i]+w/2,bm[i]+bsd[i]+0.02,f"{bm[i]:.3f}",ha="center",fontsize=8)
    ax.legend(loc="lower center",bbox_to_anchor=(0.5,1.0),ncol=2,frameon=False,fontsize=9)
    ax.spines["top"].set_visible(False); ax.spines["right"].set_visible(False)
    plt.tight_layout(); plt.savefig(os.path.join(RES,"fig_credfeature.png"),dpi=300,bbox_inches="tight")
    print("figure saved:",os.path.join(RES,"fig_credfeature.png"))

def main():
    df=build()
    for c in ["method","endpoint_norm","country","device"]:
        df[c+"_enc"]=LabelEncoder().fit_transform(df[c].astype(str))
    y=df["label"].astype(str).to_numpy(dtype=object)
    print("rows:",len(df))
    print("\nmean distinct-login-usernames per source (10s), by class:")
    print(df.groupby("label")["ip_distinct_logins_10s"].mean().round(3).to_string())
    a=cv(df,BASE+CAT,y); b=cv(df,BASE+[NEW]+CAT,y)
    print("\n{:22s} {:>18s} {:>18s} {:>9s}".format("metric","without","with","delta"))
    for k in ["macro_f1","brute_force_f1","brute_force_rec","cred_stuff_f1","cred_stuff_rec","normal_fpr"]:
        print("{:22s} {:>10.4f}+/-{:.3f} {:>10.4f}+/-{:.3f} {:>+9.4f}".format(
            k,a[k][0],a[k][1],b[k][0],b[k][1],b[k][0]-a[k][0]))
    pd.DataFrame([{"metric":k,"without_mean":a[k][0],"without_std":a[k][1],
                   "with_mean":b[k][0],"with_std":b[k][1],"delta":b[k][0]-a[k][0]}
                  for k in a]).to_csv(os.path.join(RES,"credfeature_ablation.csv"),index=False)
    figure(a,b)

if __name__=="__main__":
    main()
