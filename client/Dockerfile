FROM python:3.11-slim

# Install dependencies
RUN pip install cryptography
RUN pip install pyzmq pycryptodome bitarray numpy rsa
RUN pip install pqcrypto

WORKDIR /app
COPY . .
