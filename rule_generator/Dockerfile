FROM python:3.11-slim

RUN pip install pycryptodome
WORKDIR /app
COPY . .
CMD ["python","-u","rule_generator.py"]
