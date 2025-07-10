# VirusTotal Integration Setup Guide

Your email analyzer now includes powerful VirusTotal threat intelligence capabilities! 🛡️

## 🔑 **Step 1: Get Your VirusTotal API Key**

1. **Sign up for a free VirusTotal account:**
   - Go to: https://www.virustotal.com/
   - Click "Join our community" or "Sign up"
   - Complete registration

2. **Get your API key:**
   - Go to: https://www.virustotal.com/gui/my-apikey
   - Copy your API key

3. **Configure the API key:**
   - Open your `.env` file
   - Replace `YOUR_VIRUSTOTAL_API_KEY_HERE` with your actual API key:
   ```
   VIRUSTOTAL_API_KEY=your_actual_api_key_here
   ```

## 🔧 **Step 2: Install Required Dependencies**

```bash
pip install requests
```

## 🚀 **Step 3: Test the Integration**

Test with these prompts in the ADK web interface:

### **Test API Status:**
```
Check my VirusTotal API status and quota
```

### **Test URL Scanning:**
```
Scan this URL with VirusTotal: https://malware-traffic-analysis.net/
```

### **Test IP Scanning:**
```
Scan this IP address with VirusTotal: 8.8.8.8
```

### **Test File Hash Scanning:**
```
Scan this file hash with VirusTotal: d41d8cd98f00b204e9800998ecf8427e
```

## 📧 **Enhanced Email Analysis**

Your agent now performs comprehensive analysis:

1. **Email parsing** (headers, links, attachments, content)
2. **VirusTotal scanning** of all suspicious elements:
   - URLs found in emails
   - IP addresses from headers
   - File hashes of attachments
3. **Correlation** of local analysis with threat intelligence
4. **Enhanced threat assessment** with global reputation data

## 🛠️ **Available VirusTotal Tools**

Your agent now has these 11 tools:

### **Email Analysis Tools (7):**
1. `read_eml_file` - Read .eml files
2. `parse_email_headers` - Header analysis
3. `extract_links_from_email` - Link extraction
4. `extract_attachments_info` - Attachment analysis
5. `detect_qr_codes_in_images` - QR code detection
6. `extract_email_content` - Content extraction
7. `analyze_email_security` - Security assessment

### **VirusTotal Tools (4):**
8. `scan_url_with_virustotal` - URL threat analysis
9. `scan_file_hash_with_virustotal` - File reputation check
10. `scan_ip_with_virustotal` - IP address analysis
11. `get_virustotal_api_status` - API status check

## 📊 **API Limits (Free Tier)**

- **500 requests per day**
- **4 requests per minute**
- Perfect for email analysis use cases

## 🎯 **Example Enhanced Analysis**

Try this comprehensive email analysis:

```
Please analyze this email for security threats:

From: security@paypal-secure.tk
To: user@example.com
Subject: Account Suspended - Verify Now

Your PayPal account has been suspended. Click here to verify:
http://192.168.1.100/paypal-verify

Use VirusTotal to scan all suspicious elements you find.
```

The agent will:
1. Parse the email structure
2. Extract the suspicious URL and IP
3. Scan both with VirusTotal
4. Provide enhanced threat assessment
5. Give specific recommendations

## 🔒 **Security Benefits**

- **Global threat intelligence** from 70+ antivirus engines
- **Real-time reputation data** for URLs, IPs, and files
- **Historical analysis** of previously seen threats
- **Enhanced detection** of zero-day and emerging threats
- **Correlation** with global attack patterns

## 🚨 **Troubleshooting**

### **"API key not configured" error:**
- Check your `.env` file has the correct API key
- Restart the ADK web server after updating .env

### **"Rate limit exceeded" error:**
- Free tier: 4 requests/minute, 500/day
- Wait a minute and try again
- Consider upgrading for higher limits

### **"Resource not found" error:**
- The URL/IP/hash hasn't been seen by VirusTotal yet
- For URLs, the agent will submit them for analysis

Your email analyzer is now a powerful threat intelligence platform! 🎉 