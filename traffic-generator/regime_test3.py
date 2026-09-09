"""Regime robustness test v3 for APISentry (reviewer item 2).
5 INDEPENDENT runs: each run reseeds and regenerates traffic (source addresses,
timing jitter, request content). Sample size per scenario kept fixed for
comparable denominators. Does NOT modify the tool; only reads responses."""
import time, csv, random, requests, statistics, math

TEST_API = "http://localhost:8000"
GATEWAY  = "http://localhost:9000"
TIMEOUT  = 5
BLOCK_CODES = {403, 429}
COOLDOWN = 65
REPEATS  = 5
BASE_SEED = 1000          # run r uses seed BASE_SEED + r  (logged for reproducibility)

T975 = {1:12.706,2:4.303,3:3.182,4:2.776,5:2.571,6:2.447,7:2.365,8:2.306,9:2.262}

def get_token():
    try:
        r=requests.post(f"{TEST_API}/login",json={"username":"admin","password":"admin123"},timeout=TIMEOUT)
        return r.json().get("access_token")
    except Exception:
        return None

def send(method,path,headers=None,json=None):
    try:
        r=requests.request(method,GATEWAY+path,timeout=TIMEOUT,headers=headers,json=json)
        return r.status_code
    except Exception:
        return None

def counts(codes):
    valid=[c for c in codes if c is not None]
    return sum(1 for c in valid if c in BLOCK_CODES), len(valid)

def rip():  # random public-looking source address
    return f"{random.randint(11,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def jitter(base): time.sleep(max(0.0, random.gauss(base, base*0.3)))

# ---- generators: reseeded each run, so traffic differs run-to-run ----
def baseline_attack(t):
    ip=rip()                                   # one attacker, one (random) address this run
    codes=[]
    for i in range(25):
        codes.append(send("POST","/login",headers={"X-Forwarded-For":ip},
                          json={"username":"admin","password":f"wrong{random.randint(0,99999)}"}))
        jitter(0.02)
    return codes, {"source_ips":1,"clients":1}
def baseline_legit(t):
    ips=[rip() for _ in range(50)]             # 50 distinct random addresses this run
    random.shuffle(ips); codes=[]
    for ip in ips:
        p=random.choice(["/products",f"/products/{random.randint(1,4)}"])
        codes.append(send("GET",p,headers={"X-Forwarded-For":ip})); jitter(0.1)
    return codes, {"source_ips":50,"clients":50}
def nat_shared_legit(t):
    pool=[rip() for _ in range(3)]             # 3 random shared egress addresses this run
    codes=[]
    for i in range(50):
        p=random.choice(["/products",f"/products/{random.randint(1,4)}"])
        codes.append(send("GET",p,headers={"X-Forwarded-For":random.choice(pool)})); jitter(0.1)
    return codes, {"source_ips":3,"clients":50}
def vpn_rotate_attack(t):
    codes=[]
    for i in range(25):                        # distinct random address every request
        codes.append(send("POST","/login",headers={"X-Forwarded-For":rip()},
                          json={"username":f"user{random.randint(0,9999)}","password":f"Pass{random.randint(0,9999)}!"}))
        jitter(0.02)
    return codes, {"source_ips":25,"clients":25}
def bursty_legit(t):
    ip=rip(); codes=[]                          # one user, one random address, rapid burst
    for i in range(20):
        codes.append(send("GET",f"/products/{random.randint(1,4)}",headers={"X-Forwarded-For":ip}))
    return codes, {"source_ips":1,"clients":1}

REGIMES={
 "baseline":  {"attack":baseline_attack,  "legit":baseline_legit},
 "nat_shared":{"attack":baseline_attack,  "legit":nat_shared_legit},
 "vpn_rotate":{"attack":vpn_rotate_attack,"legit":baseline_legit},
 "bursty":    {"attack":baseline_attack,  "legit":bursty_legit},
}

def ci(vals):
    if len(vals)<2: return (None,None)
    m=statistics.mean(vals); sd=statistics.stdev(vals)
    if sd==0: return (m,m)
    t=T975.get(len(vals)-1,2.0); h=t*sd/math.sqrt(len(vals))
    return (max(0,m-h),min(1,m+h))

def main():
    token=get_token(); print("token:","ok" if token else "NONE")
    per_run=[]; agg={}
    for rep in range(1,REPEATS+1):
        seed=BASE_SEED+rep; random.seed(seed)
        print(f"\n===== INDEPENDENT RUN {rep}/{REPEATS} (seed={seed}) =====")
        for name,fns in REGIMES.items():
            t0=time.time()
            ac,am=fns["attack"](token); ab,an=counts(ac); det=ab/an if an else None
            time.sleep(COOLDOWN)
            lc,lm=fns["legit"](token);  lb,ln=counts(lc); fp=lb/ln if ln else None
            dur=round(time.time()-t0,1)
            print(f"{name:11s} det={det:.2f} ({ab}/{an})  fp={fp:.2f} ({lb}/{ln})  dur={dur}s")
            per_run.append({"run":rep,"seed":seed,"regime":name,"det":round(det,3),
                "att_block":ab,"att_total":an,"fp":round(fp,3),"legit_block":lb,"legit_total":ln,
                "att_source_ips":am["source_ips"],"att_clients":am["clients"],
                "legit_source_ips":lm["source_ips"],"legit_clients":lm["clients"],"duration_s":dur})
            a=agg.setdefault(name,{"det":[],"fp":[]}); a["det"].append(det); a["fp"].append(fp)
            time.sleep(COOLDOWN)
    summ=[]
    for name,a in agg.items():
        dcl,dch=ci(a["det"]); fcl,fch=ci(a["fp"])
        summ.append({"regime":name,"runs":len(a["det"]),
            "det_mean":round(statistics.mean(a["det"]),3),
            "det_sd":round(statistics.stdev(a["det"]),3) if len(a["det"])>1 else 0,
            "det_ci_low":None if dcl is None else round(dcl,3),
            "det_ci_high":None if dch is None else round(dch,3),
            "fp_mean":round(statistics.mean(a["fp"]),3),
            "fp_sd":round(statistics.stdev(a["fp"]),3) if len(a["fp"])>1 else 0,
            "fp_ci_low":None if fcl is None else round(fcl,3),
            "fp_ci_high":None if fch is None else round(fch,3)})
    with open("traffic-generator/regime_runs.csv","w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(per_run[0].keys())); w.writeheader(); w.writerows(per_run)
    with open("traffic-generator/regime_summary.csv","w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(summ[0].keys())); w.writeheader(); w.writerows(summ)
    print("\n===== SUMMARY (mean +/- across 5 independent runs) =====")
    for s in summ:
        print(f"{s['regime']:11s} det={s['det_mean']} (sd {s['det_sd']}) [{s['det_ci_low']},{s['det_ci_high']}]  "
              f"fp={s['fp_mean']} (sd {s['fp_sd']}) [{s['fp_ci_low']},{s['fp_ci_high']}]")
    print("\nSaved: traffic-generator/regime_runs.csv  and  traffic-generator/regime_summary.csv")

if __name__=="__main__":
    main()
