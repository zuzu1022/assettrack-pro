# PythonAnywhere Deployment Guide

Deploy your AssetTrack Pro Flask app to PythonAnywhere in 10 minutes.

---

## Step 1: Create PythonAnywhere Account

1. Go to [pythonanywhere.com](https://www.pythonanywhere.com)
2. Click **Sign Up** → Choose **Beginner** (free tier)
3. Create account with email and password
4. Verify email

---

## Step 2: Upload Your Code

### Option A: Using Git (Recommended)
```bash
# Log into PythonAnywhere Web Console
# Go to Files → Open Bash console

git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git mysite
cd mysite
```

### Option B: Upload ZIP
1. Create ZIP locally (from your project root):
```bash
zip -r assettrack-pro.zip fixed_asset_register PYTHONANYWHERE_DEPLOYMENT.md -x "*/.venv/*" "*/__pycache__/*" "*.DS_Store"
```
2. Go to **Files** tab
3. Click **Upload** → Select `assettrack-pro.zip`
4. Extract in PythonAnywhere console:
```bash
mkdir -p ~/mysite
cd ~/mysite
unzip ~/assettrack-pro.zip
```

---

## Step 3: Create Virtual Environment

In **PythonAnywhere Bash console**:

```bash
mkvirtualenv --python=/usr/bin/python3.9 mysite
pip install -r requirements.txt
```

---

## Step 4: Create Web App

1. Go to **Web** tab in dashboard
2. Click **Add a new web app**
3. Choose **Manual configuration** (or Flask if available)
4. Select **Python 3.9**
5. Click **Next**

---

## Step 5: Configure WSGI File

1. In **Web** tab, find **WSGI configuration file** section
2. Click the path shown (should be `/var/www/yourusername_pythonanywhere_com_wsgi.py`)
3. Replace the content with this:

```python
import sys
import os

# Add your project directory to the Python path
path = '/home/yourusername/mysite'
app_path = '/home/yourusername/mysite/fixed_asset_register'
if path not in sys.path:
  sys.path.insert(0, path)
if app_path not in sys.path:
  sys.path.insert(0, app_path)

# Set environment variables
os.chdir(app_path)

# Import and run your Flask app
from app import app as application

# This tells PythonAnywhere to use the 'app' object
```

**Replace `yourusername` with your PythonAnywhere username and `mysite` with your folder name.**

4. Click **Save**

---

## Step 6: Set Virtual Environment

1. In **Web** tab, find **Virtualenv** section
2. Enter the path: `/home/yourusername/.virtualenvs/mysite`
3. The green checkmark should appear
4. Click **Reload** button

---

## Step 7: Copy Database File

In **PythonAnywhere Bash console**:

```bash
# Navigate to your project app directory
cd /home/yourusername/mysite/fixed_asset_register

# Verify instance/assets.db exists
ls -la instance/assets.db

# Ensure permissions are correct
chmod 755 /home/yourusername/mysite/fixed_asset_register
chmod 755 /home/yourusername/mysite/fixed_asset_register/instance
chmod 664 /home/yourusername/mysite/fixed_asset_register/instance/assets.db
```

---

## Step 8: Check Static Files

In **Web** tab, scroll down to **Static files** section:

1. Click **Add a new static files mapping**
2. Leave **URL** as: `/static/`
3. Set **Directory** as: `/home/yourusername/mysite/fixed_asset_register/static`
4. Click the checkmark to save

---

## Step 9: Reload & Test

1. Click the green **Reload** button at top of **Web** tab
2. Wait 10 seconds
3. Visit your app URL (shown at top of Web tab)
4. **Login with:**
   - Username: `admin`
   - Password: `Admin123!`

---

## Troubleshooting

### App returns Error 500
- Check **Error log** in Web tab
- Verify virtualenv path is correct (green checkmark should appear)
- Ensure `assets.db` file exists in correct location
- Check WSGI file path imports are correct

### CSS/Images not loading
- Go to **Web** tab → **Static files** section
- Verify static file mapping path is correct
- Restart web app by clicking **Reload**

### Database not updating
- Ensure `instance/assets.db` has read/write permissions:
  ```bash
  chmod 664 /home/yourusername/mysite/fixed_asset_register/instance/assets.db
  ```

### Module import errors
- Check virtualenv is activated (green checkmark in Web tab)
- Verify `requirements.txt` installed: `pip install -r requirements.txt`
- Check app.py imports are correct

### SQLite "database is locked" errors
- SQLite has limited concurrency on shared hosting
- Consider upgrading to MySQL/PostgreSQL database for production

---

## File Paths Reference

**Replace `yourusername` with your PythonAnywhere username:**

| Item | Path |
|------|------|
| Project folder | `/home/yourusername/mysite/` |
| Flask app | `/home/yourusername/mysite/fixed_asset_register/app.py` |
| Database | `/home/yourusername/mysite/fixed_asset_register/instance/assets.db` |
| Static files | `/home/yourusername/mysite/fixed_asset_register/static/` |
| Templates | `/home/yourusername/mysite/fixed_asset_register/templates/` |
| Virtual env | `/home/yourusername/.virtualenvs/mysite` |

---

## Default Credentials

After deployment, login with:

| Role | Username | Password |
|------|----------|----------|
| Admin | `admin` | `Admin123!` |
| Viewer | `viewer` | `Viewer123!` |

**Change these passwords after first login!**

---

## Next Steps

1. Test all features (assets, approvals, reports)
2. Change default passwords
3. Configure email alerts (optional, requires premium PythonAnywhere)
4. Set up automated backups of `assets.db`
5. Consider upgrading to paid tier for custom domain

---

## Support

- **PythonAnywhere Help:** https://www.pythonanywhere.com/help/
- **PythonAnywhere Forums:** https://www.pythonanywhere.com/forums/
- **Flask Documentation:** https://flask.palletsprojects.com/
