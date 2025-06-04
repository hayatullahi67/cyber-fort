# Cyber Fort

A security tool for checking URLs and phone numbers.

## Deployment on Render

### Prerequisites
1. A Render account
2. A VirusTotal API key

### Deployment Steps

1. Fork or clone this repository to your GitHub account

2. Go to [Render Dashboard](https://dashboard.render.com)

3. Click "New +" and select "Web Service"

4. Connect your GitHub repository

5. Configure the service:
   - Name: cyber-fort (or your preferred name)
   - Environment: Node
   - Build Command: `npm install && npm run build`
   - Start Command: `npm start`

6. Add Environment Variables:
   - `VIRUSTOTAL_API_KEY`: Your VirusTotal API key
   - `NODE_ENV`: production

7. Click "Create Web Service"

### Environment Variables

The following environment variables are required:

- `VIRUSTOTAL_API_KEY`: Your VirusTotal API key for URL scanning
- `NODE_ENV`: Set to "production" for production deployment

### API Endpoints

- URL Check: `POST /api/check-url`
  - Body: `{ "url": "https://example.com" }`

- Phone Check: `POST /api/check-phone`
  - Body: `{ "phoneNumber": "+1234567890" }`

## Local Development

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create a `.env` file with required environment variables:
   ```
   VIRUSTOTAL_API_KEY=your_api_key_here
   ```

3. Start the development server:
   ```bash
   npm run dev
   ```