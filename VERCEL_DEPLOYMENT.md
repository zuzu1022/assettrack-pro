# Deploy AssetTrack Pro to Vercel

Your Flask app is configured for Vercel! Follow these steps to go live in minutes.

## Prerequisites

1. **GitHub Account** - Free at https://github.com/signup
2. **Vercel Account** - Free at https://vercel.com/signup

## Step 1: Push Code to GitHub

```bash
# Navigate to your project directory
cd "/Users/zainab/Fixed Asset Register and Depreciation Tracking System"

# Create a new GitHub repository (then copy the remote URL)
# https://github.com/new

# Add remote and push
git remote add origin https://github.com/YOUR_USERNAME/assettrack-pro.git
git branch -M main
git push -u origin main
```

## Step 2: Deploy on Vercel

1. Go to https://vercel.com/new
2. **Import** your GitHub repository
3. Select `assettrack-pro` repo
4. Click **Import**
5. Vercel will auto-detect your `vercel.json` configuration
6. Click **Deploy**

## Step 3: Set Environment Variables (Optional)

If you need custom environment variables:
1. Go to **Settings** → **Environment Variables**
2. Add any needed variables
3. Redeploy

## After Deployment

✅ Your app is live at: `https://assettrack-pro-RANDOMID.vercel.app`

### Login Credentials
- **Admin**: `admin` / `Admin123!`
- **Viewer**: `viewer` / `Viewer123!`

---

## ⚠️ Important: Database Persistence

**Note:** Vercel is serverless with ephemeral storage. SQLite database resets after deployments.

For production, migrate to PostgreSQL:
1. Get a free PostgreSQL database from:
   - [Neon](https://neon.tech) (Recommended)
   - [Railway.app](https://railway.app)
   - [Heroku](https://www.heroku.com)

2. Update `SQLALCHEMY_DATABASE_URI` in `fixed_asset_register/app.py`:
   ```python
   app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://user:password@host/dbname"
   ```

3. Redeploy to Vercel

---

## Troubleshooting

- **Deployment fails**: Check build logs in Vercel dashboard
- **404 errors**: Ensure `vercel.json` routing is correct
- **Static files missing**: CSS loads from `/static/css/style.css` path

Need help? Check Vercel docs: https://vercel.com/docs/concepts/functions/serverless-functions
Sat Aug 22 18:21:09 +03 2026
