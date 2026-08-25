# Oracle Always Free Deployment (Django)

This project can run on a single Oracle Linux/Ubuntu VM with `gunicorn` + `nginx`.

## 1) Create VM and open ports

1. Create an Always Free VM in Oracle Cloud (Ampere A1 works well).
2. In Oracle VCN security list and/or NSG, allow inbound:
   - `22` (SSH)
   - `80` (HTTP)
   - `443` (HTTPS, if you add TLS)

## 2) Install system packages

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip nginx git
```

## 3) Clone and install app

```bash
sudo mkdir -p /opt/agentpayments
sudo chown -R $USER:$USER /opt/agentpayments
cd /opt/agentpayments
git clone <YOUR_REPO_URL> .
python3 -m venv /opt/agentpayments/.venv
source /opt/agentpayments/.venv/bin/activate
pip install --upgrade pip
pip install -r python_implementation/django/requirements.txt
```

## 4) Configure environment

```bash
cp /opt/agentpayments/python_implementation/django/.env.example /opt/agentpayments/python_implementation/django/.env
```

Edit `python_implementation/django/.env`:

```dotenv
DJANGO_SECRET_KEY=<strong-random-secret>
CHALLENGE_SECRET=<strong-random-secret>
AGENTPAYMENTS_VERIFY_URL=https://your-verify-service.example.com/verify
AGENTPAYMENTS_API_KEY=<your-api-key>
ALLOWED_HOSTS=<your-domain-or-public-ip>
CSRF_TRUSTED_ORIGINS=http://<your-domain-or-public-ip>
```

If you later add TLS, set `CSRF_TRUSTED_ORIGINS` to `https://...`.

## 5) Validate Django config

```bash
source /opt/agentpayments/.venv/bin/activate
python3 /opt/agentpayments/python_implementation/django/manage.py check
```

## 6) Install systemd service

```bash
sudo cp /opt/agentpayments/python_implementation/django/deploy/oracle/agentpayments.service /etc/systemd/system/agentpayments.service
sudo systemctl daemon-reload
sudo systemctl enable --now agentpayments
sudo systemctl status agentpayments --no-pager
```

## 7) Configure nginx

```bash
sudo cp /opt/agentpayments/python_implementation/django/deploy/oracle/nginx-agentpayments.conf /etc/nginx/sites-available/agentpayments
sudo ln -sf /etc/nginx/sites-available/agentpayments /etc/nginx/sites-enabled/agentpayments
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl restart nginx
```

## 8) Verify

```bash
curl -i http://<server-ip>/
curl -i http://<server-ip>/.well-known/agent-access.json
```

## HTTPS on Oracle (recommended)

You need a real domain pointed at the VM public IP (Let's Encrypt won't issue trusted certs for raw IPs).

### 1) Point DNS
- Create an `A` record, e.g. `pay.yourdomain.com -> <vm-public-ip>`
- Wait for propagation.

### 2) Update nginx server_name
Edit `/etc/nginx/sites-available/agentpayments` and replace `server_name _;` with your domain:

```nginx
server_name pay.yourdomain.com;
```

Then reload nginx:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 3) Issue certificate with Certbot

```bash
sudo apt update
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d pay.yourdomain.com --redirect -m you@example.com --agree-tos --no-eff-email
```

This will:
- install TLS certs
- add HTTPS server block(s)
- auto-redirect HTTP -> HTTPS

### 4) Confirm auto-renew

```bash
sudo systemctl status certbot.timer --no-pager
sudo certbot renew --dry-run
```

### 5) Django env update
Set CSRF trusted origins to HTTPS origin in `python_implementation/django/.env`:

```dotenv
CSRF_TRUSTED_ORIGINS=https://pay.yourdomain.com
```

Then restart app service:

```bash
sudo systemctl restart agentpayments
```
