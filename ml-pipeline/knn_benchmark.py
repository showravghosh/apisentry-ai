"""Item 8: single-request inference latency and model size for CatBoost, Random
Forest and KNN, measured under one consistent method on the frozen processed
dataset. Reproduces the CatBoost/RF figures as a sanity check, then adds KNN."""
import time, os, json, tempfile, statistics, joblib
import numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from catboost import CatBoostClassifier

df=pd.read_csv("ml-pipeline/processed/dataset_processed.csv")
feats=json.load(open("ml-pipeline/processed/feature_columns.json"))
X=df[feats]; y=df["label"].astype(str)
Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=0.2,random_state=42,stratify=y)
Xte_np=Xte.to_numpy(); Xtr_np=Xtr.to_numpy()

def size_mb(model,kind):
    f=tempfile.mktemp()
    if kind=="cb": model.save_model(f)
    else: joblib.dump(model,f)
    s=os.path.getsize(f)/1e6; os.remove(f); return s

def latency_ms(predict_one,n=500):
    rng=np.random.RandomState(0); idx=rng.randint(0,len(Xte_np),size=n)
    predict_one(Xte_np[idx[0]:idx[0]+1])           # warmup
    ts=[]
    for i in idx:
        t0=time.perf_counter(); predict_one(Xte_np[i:i+1]); ts.append((time.perf_counter()-t0)*1000)
    return statistics.mean(ts)

print("training models on frozen processed dataset ...")
cb=CatBoostClassifier(iterations=400,depth=8,learning_rate=0.1,loss_function="MultiClass",
                      auto_class_weights="Balanced",random_seed=42,verbose=False); cb.fit(Xtr,ytr)
rf=RandomForestClassifier(n_estimators=300,class_weight="balanced",random_state=42,n_jobs=1); rf.fit(Xtr,ytr)
knn=KNeighborsClassifier(n_neighbors=5); knn.fit(Xtr_np,ytr)

print(f"\n{'Model':16s} {'latency (ms)':>13s} {'size (MB)':>11s}")
print(f"{'CatBoost':16s} {latency_ms(cb.predict):>13.2f} {size_mb(cb,'cb'):>11.2f}")
print(f"{'Random Forest':16s} {latency_ms(rf.predict):>13.2f} {size_mb(rf,'pkl'):>11.2f}")
print(f"{'KNN (k=5)':16s} {latency_ms(knn.predict):>13.2f} {size_mb(knn,'pkl'):>11.2f}")
