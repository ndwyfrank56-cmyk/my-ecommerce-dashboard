# Cloudinary Setup Guide (FREE - No Credit Card Needed!)

Your dashboard is now configured to use **Cloudinary** for image storage. This is perfect because:
- ✅ **FREE** - No credit card required
- ✅ **Cloud-based** - Both dashboard and website can access images
- ✅ **Easy setup** - Takes 2 minutes
- ✅ **Generous free tier** - 25GB storage + 25GB bandwidth/month

## Step 1: Sign Up (FREE)
1. Go to https://cloudinary.com/users/register/free
2. Enter your email and create a password
3. **No credit card needed!**
4. Click "Create Account"

## Step 2: Get Your Credentials
1. You'll be taken to your Dashboard
2. Look for the **"Account Details"** section at the top
3. You'll see three things you need:
   - **Cloud Name** (looks like: `dh1234567`)
   - **API Key** (looks like: `123456789012345`)
   - **API Secret** (looks like: `abc123xyz789`)

## Step 3: Add Credentials to Your Dashboard
1. Open your `.env` file in the dashboard folder
2. Add these three lines:

```env
CLOUDINARY_CLOUD_NAME=your-cloud-name-here
CLOUDINARY_API_KEY=your-api-key-here
CLOUDINARY_API_SECRET=your-api-secret-here
```

Example:
```env
CLOUDINARY_CLOUD_NAME=dh1234567
CLOUDINARY_API_KEY=123456789012345
CLOUDINARY_API_SECRET=abc123xyz789
```

## Step 4: Install Dependencies
Run this command in your dashboard folder:

```bash
pip install -r requirements.txt
```

This installs the Cloudinary Python library.

## Step 5: Test It
1. Start your dashboard
2. Try uploading a product image
3. Check your Cloudinary Dashboard at https://cloudinary.com/console
4. You should see your images in the "Media Library"

## How It Works
- **Product images** → Stored in `/products` folder on Cloudinary
- **Variation images** → Stored in `/variations` folder on Cloudinary
- **URLs** → Images get public URLs like:
  ```
  https://res.cloudinary.com/dh1234567/image/upload/v1234567890/products/product-name.jpg
  ```

## Free Tier Limits
- **Storage**: 25 GB
- **Bandwidth**: 25 GB/month
- **Transformations**: Unlimited
- **API calls**: 500,000/month

For most small ecommerce sites, you'll never hit these limits!

## Troubleshooting

### "Cloudinary not configured" error
- Check that all 3 credentials are in your `.env` file
- Restart your Flask app after updating `.env`
- Make sure there are no extra spaces or quotes

### Images not uploading
- Verify credentials are correct (copy-paste from Cloudinary dashboard)
- Check your Cloudinary account is active (check email)
- Look at the error message in the console

### Images not showing on website
- Make sure the image URL is being saved to the database
- Check that Cloudinary URLs are accessible (they're public by default)

## Next Steps
1. Update your website to use the same Cloudinary account
2. Both dashboard and website will share the same image storage
3. No more local file path issues!

## Support
- Cloudinary Docs: https://cloudinary.com/documentation
- Dashboard: https://cloudinary.com/console
