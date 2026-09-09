"""5-seed firewall comparison (APISentry vs ModSecurity), addressing uneven-rigor
review point for RQ4. Repeats the live comparison over 5 independent seeded runs,
regenerating source addresses, timing and payload order each run, and reports
mean +/- 95% CI (and std) across runs. ModSecurity is expected to be deterministic
(std ~ 0); this run makes that explicit rather than assumed.

Requires: gateway on :9000 (./run.sh) AND ModSecurity on :8081
(docker compose -f baseline/docker-compose.yml up -d)."""
import time, csv, random, statistics, math, requests

TEST_API="http://localhost:8000"
TARGETS={"ModSecurity (CRS)":"http://localhost:8081","APISentry":"http://localhost:9000"}
N=25; TIMEOUT=5; BLOCK={403,429}; REPEATS=5; BASE_SEED=2000
T975={1:12.706,2:4.303,3:3.182,4:2.776}   # df=REPEATS-1=4 -> 2.776

def token():
    try: return requests.post(f"{TEST_API}/login",json={"username":"admin","password":"admin123"},timeout=TIMEOUT).json().get("access_token")
    except: return None
def send(base,method,path,**kw):
    try: return requests.request(method,base+path,timeout=TIMEOUT,**kw).status_code
    except: return None
def rip(): return f"{random.randint(11,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
def jit(b): time.sleep(max(0.0,random.gauss(b,b*0.3)))

def atk_sql(base,t):
    pays=["' OR '1'='1","1' UNION SELECT username,password FROM users--","'; DROP TABLE users;--","admin'--","1 OR 1=1"]
    random.shuffle(pays); c=[]
    for i in range(N): c.append(send(base,"GET",f"/search?q={requests.utils.quote(pays[i%len(pays)])}")); jit(0.02)
    return c
def atk_tamper(base,t):
    h={"Authorization":f"Bearer {t}"} if t else {}; c=[]
    for i in range(N): c.append(send(base,"POST","/cart/add",json={"product_id":-random.randint(1,99999),"quantity":-random.randint(1,99999)},headers=h)); jit(0.02)
    return c
def atk_bola(base,t):
    h={"Authorization":f"Bearer {t}"} if t else {}; ids=list(range(1,N+1)); random.shuffle(ids); c=[]
    for i in ids: c.append(send(base,"GET",f"/users/{i}",headers=h)); jit(0.02)
    return c
def atk_brute(base,t):
    c=[]
    for i in range(N): c.append(send(base,"POST","/login",json={"username":"admin","password":f"wrong{random.randint(0,99999)}"})); jit(0.02)
    return c
def atk_cred(base,t):
    c=[]
    for i in range(N): c.append(send(base,"POST","/login",json={"username":f"user{random.randint(0,9999)}","password":f"Pass{random.randint(0,9999)}!"})); jit(0.02)
    return c
def atk_flood(base,t):
    c=[]
    for i in range(N*2): c.append(send(base,"GET","/products"))
    return c
def atk_replay(base,t):
    h={"Authorization":f"Bearer {t}"} if t else {}; c=[]
    for i in range(N):
        hh=dict(h); hh["X-Forwarded-For"]=rip(); c.append(send(base,"GET","/cart",headers=hh)); jit(0.02)
    return c
def normal(base,t):
    c=[]
    for i in range(N*2):
        h={"X-Forwarded-For":rip()}; ep="/products" if i%2==0 else f"/products/{random.randint(1,4)}"
        c.append(send(base,"GET",ep,headers=h)); jit(0.1)
    return c

ATTACKS={"sql_injection":atk_sql,"parameter_tampering":atk_tamper,"bola":atk_bola,
         "brute_force":atk_brute,"credential_stuffing":atk_cred,"api_flooding":atk_flood,"token_replay":atk_replay}
def rate(codes):
    v=[c for c in codes if c is not None]; return (sum(1 for c in v if c in BLOCK)/len(v)) if v else None

def ci(vs):
    if len(vs)<2: return (vs[0],vs[0]) if vs else (None,None)
    m=statistics.mean(vs); sd=statistics.stdev(vs)
    if sd==0: return (m,m)
    h=T975.get(len(vs)-1,2.78)*sd/math.sqrt(len(vs)); return (max(0,m-h),min(1,m+h))

def main():
    tk=token(); print("token:","ok" if tk else "NONE")
    acc={a:{s:[] for s in TARGETS} for a in list(ATTACKS)+["normal_fp"]}
    for rep in range(1,REPEATS+1):
        random.seed(BASE_SEED+rep); print(f"\n=== run {rep}/{REPEATS} (seed {BASE_SEED+rep}) ===")
        for a,fn in ATTACKS.items():
            for s,base in TARGETS.items():
                acc[a][s].append(rate(fn(base,tk))); time.sleep(1)
        time.sleep(65)  # decay before FP test
        for s,base in TARGETS.items():
            acc["normal_fp"][s].append(rate(normal(base,tk))); time.sleep(1)
        print("  done")
    rows=[]
    for a in list(ATTACKS)+["normal_fp"]:
        r={"attack":a}
        for s in TARGETS:
            vs=[x for x in acc[a][s] if x is not None]; m=statistics.mean(vs) if vs else float("nan")
            sd=statistics.stdev(vs) if len(vs)>1 else 0.0; lo,hi=ci(vs)
            r[f"{s} mean"]=round(m,3); r[f"{s} sd"]=round(sd,3); r[f"{s} CI"]=f"[{lo:.3f},{hi:.3f}]"
        rows.append(r)
    with open("baseline/comparison5_results.csv","w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    print("\n===== SUMMARY (mean [95% CI], sd across 5 runs) =====")
    for r in rows:
        print(r["attack"], "|", " | ".join(f"{s}={r[s+' mean']} {r[s+' CI']} sd={r[s+' sd']}" for s in TARGETS))
    print("\nSaved baseline/comparison5_results.csv")

if __name__=="__main__": main()
