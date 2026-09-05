# SigmawealthSolution Backend API

Express API backend for SigmawealthSolution deployed on Render.

## Features
- Full investor auth, profiles, and admin management
- Flutterwave v4 card tokenization, direct charge, and automated disbursements
- Zero-CORS configuration for seamless Vercel frontend connectivity
- Robust offline fallbacks and healthchecks (/ and /health)

## Render Deployment Settings
- **Environment**: Node
- **Build Command**: 
pm install && npm run build
- **Start Command**: 
pm start (or 
ode dist/sigma-api.js)
- **Health Check Path**: /health

## Environment Variables
- PORT: (Auto-set by Render, defaults to 4000)
- ALLOWED_ORIGINS: https://your-frontend.vercel.app
- NEXT_PUBLIC_SUPABASE_URL: (Your Supabase project URL)
- SUPABASE_SERVICE_ROLE_KEY: (Your Supabase service role key)
- FLUTTERWAVE_CLIENT_ID: (Flutterwave Client ID)
- FLUTTERWAVE_CLIENT_SECRET: (Flutterwave Secret Key)
- FLUTTERWAVE_ENCRYPTION_KEY: (Flutterwave Encryption Key)
- FLUTTERWAVE_WEBHOOK_SECRET: (Webhook Secret Hash)
- OPAY_ACCOUNT_NAME: (Optional OPay account name)
- OPAY_ACCOUNT_NUMBER: (Optional OPay account number)
- OPAY_BANK_NAME: (Optional OPay bank name)
