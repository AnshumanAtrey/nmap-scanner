FROM apify/actor-python:3.13

# Install nmap binary + NSE script support
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    ncat \
    && rm -rf /var/lib/apt/lists/*

# Verify nmap is installed and show version at build time
RUN nmap --version | head -3

COPY requirements.txt /actor/requirements.txt
RUN pip install --no-cache-dir -r /actor/requirements.txt

COPY . /actor
WORKDIR /actor

CMD ["python3", "-m", "src.main"]
