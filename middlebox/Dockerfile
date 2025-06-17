FROM python:3.11-slim

# Install dependencies
RUN pip install cryptography
RUN apt update && apt install -y tcpdump

WORKDIR /app
COPY middlebox.py .
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

#CMD ["python","-u","middlebox.py"]
ENTRYPOINT ["./entrypoint.sh"]