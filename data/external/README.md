# External benchmarks

The external-validation experiments (Tables 13 and 14) use two public third-party datasets, which are not redistributed here because of their own licences. Download them and place them as follows, then run `offline/e11_external.py` with `APISENTRY_EXT=<this folder>`:

- **CSIC 2010** (HTTP DATASET CSIC 2010): place `normalTrafficTraining.txt` and `anomalousTrafficTest.txt` in `csic/`.
- **ECML/PKDD 2007** (Web Application Attack dataset): place the train/test files in `ecml/`.

`e11_external.py` parses the raw HTTP requests, extracts the gateway's payload features, and also fits the character n-gram TF-IDF reference model, writing `results/e11_external.json`.
