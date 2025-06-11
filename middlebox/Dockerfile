FROM python:3.11-slim

# Install dependencies
RUN pip install cryptography

WORKDIR /app
COPY middlebox.py .
CMD ["python", "middlebox.py"]
