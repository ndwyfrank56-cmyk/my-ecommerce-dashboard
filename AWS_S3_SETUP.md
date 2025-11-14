# AWS S3 Setup Guide for Image Uploads

Your dashboard is now configured to use **AWS S3** for image storage instead of local files. This allows both your dashboard and website (deployed separately) to access the same images.

## Step 1: Create AWS Account
1. Go to https://aws.amazon.com
2. Click "Create an AWS Account"
3. Follow the registration process

## Step 2: Create IAM User with S3 Access
1. Log in to AWS Console
2. Go to **IAM** (Identity and Access Management)
3. Click **Users** → **Create User**
4. Enter username (e.g., `ecommerce-dashboard`)
5. Click **Next**
6. Click **Attach policies directly**
7. Search for and select: **AmazonS3FullAccess**
8. Click **Next** → **Create User**

## Step 3: Create Access Keys
1. Go back to **Users** and click on your newly created user
2. Click **Security credentials** tab
3. Scroll to **Access keys** section
4. Click **Create access key**
5. Select **Application running outside AWS**
6. Click **Next**
7. Click **Create access key**
8. **Copy and save** both:
   - Access Key ID
   - Secret Access Key
   
   ⚠️ **IMPORTANT**: Save these securely! You won't see the secret key again.

## Step 4: Create S3 Bucket
1. Go to **S3** service
2. Click **Create bucket**
3. Enter bucket name (e.g., `ecommerce-images-ndwyfrank56`)
   - Must be globally unique
   - Use lowercase letters, numbers, hyphens
4. Select region (e.g., `us-east-1`)
5. Click **Create bucket**

## Step 5: Configure Bucket Permissions (Public Read Access)
1. Click on your bucket
2. Go to **Permissions** tab
3. Scroll to **Block public access** → Click **Edit**
4. **Uncheck** all options (to allow public read)
5. Click **Save changes**
6. Go to **Bucket Policy** → Click **Edit**
7. Paste this policy (replace `your-bucket-name`):

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicReadGetObject",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::your-bucket-name/*"
        }
    ]
}
```

8. Click **Save changes**

## Step 6: Update Your Dashboard .env File
Add these variables to your `.c:\Users\Public\ecommerce dashbord\.env` file:

```env
AWS_ACCESS_KEY_ID=your-access-key-id-here
AWS_SECRET_ACCESS_KEY=your-secret-access-key-here
AWS_S3_BUCKET_NAME=your-bucket-name
AWS_S3_REGION=us-east-1
```

Example:
```env
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPlusCfrISMNDAqwlzj
AWS_S3_BUCKET_NAME=ecommerce-images-ndwyfrank56
AWS_S3_REGION=us-east-1
```

## Step 7: Install Dependencies
Run this command in your dashboard folder:

```bash
pip install -r requirements.txt
```

This installs boto3 (AWS SDK for Python).

## Step 8: Test It
1. Start your dashboard
2. Try uploading a product image
3. Check if the image appears in your S3 bucket at: https://s3.console.aws.amazon.com
4. The image URL should look like: `https://your-bucket-name.s3.us-east-1.amazonaws.com/products/image-name.jpg`

## Troubleshooting

### "AWS S3 not configured" error
- Check that all 4 environment variables are set in `.env`
- Restart your Flask app after updating `.env`

### "Access Denied" error
- Verify your Access Key ID and Secret Access Key are correct
- Check that the IAM user has `AmazonS3FullAccess` policy attached
- Make sure the bucket name matches exactly

### Images not showing on website
- Verify bucket policy allows public read access
- Check that the image URL is correct
- Make sure CORS is configured if website is on different domain

## Pricing
- **First 5GB/month**: FREE
- **After 5GB**: ~$0.023 per GB
- **Requests**: ~$0.0004 per 1000 requests

For most small ecommerce sites, you'll stay within the free tier.

## Next Steps
- Update your website to use the same S3 bucket for images
- Both dashboard and website will now share the same image storage
- No more local file path issues!
