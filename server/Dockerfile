FROM python:3.11-slim

# Install dependencies
RUN pip install cryptography
RUN pip install pyzmq pycryptodome bitarray
RUN pip install pqcrypto
RUN pip install tinyec

WORKDIR /app

COPY . .

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]