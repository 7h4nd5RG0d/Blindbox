FROM python:3.11-slim

# Install dependencies
RUN pip install cryptography
RUN pip install pyzmq pycryptodome bitarray
# Install dependencies including git
RUN apt-get update && apt-get install -y git 

WORKDIR /app

COPY server.py .
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]