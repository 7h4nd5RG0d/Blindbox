# Blindbox
Blindbox-implementation


# Running
1) Run this in the source directory  
```bash
docker-compose build
```
2) 
```bash
docker-compose up -d
```

3) Client 
```bash
docker exec -it client python client.py
```

4) For viewing the logs of middlebox and server, open another terminal and run:
```bash
docker-compose logs -f
```

5) After finishing the session, make sure to run, 
```bash
docker-compose down
```
before starting new session

# Code intuition and explanation:

[📄 Read the full documentation (PDF)](Blindbox.pdf)

# Referances:
https://o1-labs.github.io/proof-systems/fundamentals/zkbook_2pc/overview.html  
https://encrypt.a41.io/mpc/yaos-garbled-circuits#half-gates  
https://securecomputation.org/  
https://giapppp.github.io/posts/ygc/  
