# domain-security-analyzer
# Screenshots

## Web Dashboard

![Web Dashboard](screenshots/web_dashboard.png)

## Terminal Dashboard

![Terminal Dashboard](screenshots/terminal_dashboard.png)

# Installation

## Windows

### Clone Repository

```powershell
git clone https://github.com/suryanagalingam877-code/domain-security-analyzer.git

cd domain-security-analyzer
```

### Create Virtual Environment

```powershell
python -m venv venv
```

### Activate Virtual Environment

```powershell
venv\Scripts\activate
```

### Install Dependencies

```powershell
pip install -r requirements.txt
```

### Run Web Dashboard

```powershell
python web_app.py
```

Browser opens automatically:

```text
http://127.0.0.1:5000
```

---

## Linux (Kali / Ubuntu / Debian)

### Clone Repository

```bash
git clone https://github.com/suryanagalingam877-code/domain-security-analyzer.git

cd domain-security-analyzer
```

### Install Python

```bash
sudo apt update

sudo apt install python3 python3-pip python3-venv dnsutils whois -y
```

### Create Virtual Environment

```bash
python3 -m venv venv
```

### Activate Virtual Environment

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Terminal Dashboard

```bash
python3 analyzer.py
```

---

## Updating The Tool

Pull latest version:

```bash
git pull origin main
```

Install any new packages:

```bash
pip install -r requirements.txt
```

---

## Developer Installation

Install manually:

```bash
pip install flask
pip install rich
pip install dnspython
pip install requests
pip install python-whois
pip install cryptography
pip install jinja2
pip install aiohttp
pip install beautifulsoup4
pip install tldextract
```

or

```bash
pip install -r requirements.txt
```

---

## Verify Installation

```bash
python --version
```

or

```bash
python3 --version
```

Then:

```bash
python analyzer.py
```

or

```bash
python web_app.py
```
