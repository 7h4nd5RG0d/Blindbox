FROM python:3.11-slim

# Install dependencies
RUN pip install cryptography
RUN apt update && apt install -y tcpdump
RUN pip install pyzmq pycryptodome bitarray numpy rsa
RUN pip install tinyec
# Install dependencies including git
RUN apt-get update && apt-get install -y git 
WORKDIR /app
COPY . .
RUN chmod +x entrypoint.sh
#CMD ["python","-u","middlebox.py"]
ENTRYPOINT ["./entrypoint.sh"]