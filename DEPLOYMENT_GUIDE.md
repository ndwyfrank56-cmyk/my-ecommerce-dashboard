# 🚀 Dashboard Deployment Guide

## Quick Deploy to Render

### Step 1: Generate Secret Key
Run this command:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```
**Copy the output!**

### Step 2: Push to GitHub
```bash
cd "c:\Users\Public\ecommerce dashbord"
git init
git add .
git commit -m "Dashboard ready for deployment"

# Create repo on GitHub: ecommerce-dashboard
git remote add origin https://github.com/YOUR_USERNAME/ecommerce-dashboard.git
git branch -M main
git push -u origin main
```

### Step 3: Deploy on Render

1. Go to: https://dashboard.render.com/
2. Click **+ New** → **Web Service**
3. Connect your `ecommerce-dashboard` repository
4. Configure:
   - **Name:** ecommerce-dashboard
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn -c gunicorn_config.py app:app`

### Step 4: Environment Variables

**IMPORTANT:** Use the SAME database credentials as your website!

Add these in Render's Environment tab:

```bash
# SECRET KEY (generate new one!)
SECRET_KEY=<paste-your-generated-key>

# Flask Config
FLASK_ENV=production

# Database (COPY from your website's environment variables!)
DB_HOST=<copy-from-website>
DB_USER=<copy-from-website>
DB_PASSWORD=<copy-from-website>
DB_NAME=ecommerce
DB_PORT=<copy-from-website-or-use-3306>

# Email
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=465
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password
MAIL_USE_TLS=False
MAIL_USE_SSL=True

# Security
SESSION_COOKIE_SECURE=True
SESSION_COOKIE_HTTPONLY=True
SESSION_COOKIE_SAMESITE=Lax
PERMANENT_SESSION_LIFETIME=3600

# Performance
CACHE_TYPE=SimpleCache
RATELIMIT_STORAGE_URL=memory://
```

### Step 5: Get Database Credentials

1. In Render dashboard, click your **My-E-commerce-Website** service
2. Go to **Environment** tab
3. Copy: `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_PORT`
4. Paste into dashboard's environment variables

**Important for Railway/External Databases:**
- Always copy the exact `DB_PORT` value (Railway uses non-standard ports)
- Verify `DB_HOST` includes the full proxy address

### Step 6: Deploy!

Click **Create Web Service** and wait ~3-5 minutes.

Your dashboard will be live at: `https://ecommerce-dashboard.onrender.com`

---

## ✅ Testing

After deployment:
- [ ] Visit dashboard URL
- [ ] Login works
- [ ] Orders from website appear
- [ ] Products sync correctly
- [ ] All pages load

---

## 🔒 Gmail App Password Setup

1. Go to: https://myaccount.google.com/apppasswords
2. Enable 2-Step Verification (if not enabled)
3. Generate App Password for "Mail"
4. Copy 16-character password
5. Use in `MAIL_PASSWORD` variable

---

## 🆘 Troubleshooting

### Build fails
- Check `requirements.txt` has all dependencies
- Check Python version in `runtime.txt`

### Database connection error (Can't connect to server)
- **CRITICAL:** Verify `DB_PORT` environment variable is set correctly
- For Railway databases, copy the exact port number from your database config
- Verify all DB credentials (`DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_PORT`) match your website exactly
- Check that `DB_HOST` includes the full proxy address (e.g., `caboose.proxy.rlwy.net`)

### "Application failed to respond"
- Check logs in Render dashboard
- Verify all environment variables are set

---

**Need help?** Check the logs in Render dashboard for error details.
