#!/bin/bash

# Web Security Scanner Script
# Usage: ./web_security_scan.sh <target_url>

TARGET_URL=$1
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="reports"
REPORT_FILE="$REPORT_DIR/security_report_$TIMESTAMP.html"

# Create report directory
mkdir -p $REPORT_DIR

echo "🔍 Starting Security Scan for: $TARGET_URL"

# HTML Report Header
cat > $REPORT_FILE << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Security Report - $TARGET_URL</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
        h1 { color: #d9534f; border-bottom: 3px solid #d9534f; padding-bottom: 10px; }
        h2 { color: #5bc0de; border-bottom: 2px solid #5bc0de; margin-top: 30px; }
        .critical { background: #f8d7da; color: #721c24; padding: 10px; border-left: 4px solid #dc3545; margin: 10px 0; }
        .warning { background: #fff3cd; color: #856404; padding: 10px; border-left: 4px solid #ffc107; margin: 10px 0; }
        .success { background: #d4edda; color: #155724; padding: 10px; border-left: 4px solid #28a745; margin: 10px 0; }
        .info { background: #d1ecf1; color: #0c5460; padding: 10px; border-left: 4px solid #17a2b8; margin: 10px 0; }
        pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; }
        table { border-collapse: collapse; width: 100%; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #5bc0de; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .badge { padding: 5px 10px; border-radius: 3px; font-weight: bold; }
        .badge-danger { background: #dc3545; color: white; }
        .badge-warning { background: #ffc107; color: #212529; }
        .badge-success { background: #28a745; color: white; }
    </style>
</head>
<body>
<div class="container">
    <h1>🔐 Security Scan Report</h1>
    <div class="info">
        <strong>Target:</strong> $TARGET_URL<br>
        <strong>Scan Date:</strong> $(date)<br>
        <strong>Scan ID:</strong> $TIMESTAMP
    </div>
EOF

# 1. SSL/TLS Check
echo "<h2>1. 🔒 SSL/TLS Configuration</h2>" >> $REPORT_FILE
echo "Checking SSL/TLS..."
if command -v sslscan &> /dev/null; then
    echo "<pre>" >> $REPORT_FILE
    timeout 30 sslscan --no-failed $TARGET_URL 2>&1 | head -50 >> $REPORT_FILE
    echo "</pre>" >> $REPORT_FILE
else
    echo "<div class='warning'>⚠️ SSLScan not available</div>" >> $REPORT_FILE
fi

# 2. Security Headers Check
echo "<h2>2. 🛡️ Security Headers Analysis</h2>" >> $REPORT_FILE
echo "Checking security headers..."
python3 << 'PYEOF' >> $REPORT_FILE
import requests
import sys

target = "$TARGET_URL"

try:
    response = requests.get(target, timeout=10, verify=False)
    headers = response.headers
    
    print("<table>")
    print("<tr><th>Security Header</th><th>Status</th><th>Value</th><th>Risk Level</th></tr>")
    
    security_headers = {
        'Strict-Transport-Security': ('CRITICAL', 'Prevents MITM attacks'),
        'Content-Security-Policy': ('HIGH', 'Prevents XSS attacks'),
        'X-Frame-Options': ('MEDIUM', 'Prevents clickjacking'),
        'X-Content-Type-Options': ('MEDIUM', 'Prevents MIME sniffing'),
        'X-XSS-Protection': ('LOW', 'Browser XSS filter'),
        'Referrer-Policy': ('LOW', 'Controls referrer info'),
        'Permissions-Policy': ('MEDIUM', 'Controls browser features')
    }
    
    missing_critical = []
    
    for header, (risk, desc) in security_headers.items():
        if header in headers:
            badge = 'success'
            status = '✓ Present'
            value = headers[header][:100]
        else:
            status = '✗ Missing'
            value = '-'
            if risk == 'CRITICAL':
                badge = 'danger'
                missing_critical.append(header)
            elif risk == 'HIGH':
                badge = 'warning'
            else:
                badge = 'warning'
        
        print(f"<tr>")
        print(f"<td><strong>{header}</strong><br><small>{desc}</small></td>")
        print(f"<td>{status}</td>")
        print(f"<td><code>{value}</code></td>")
        print(f"<td><span class='badge badge-{badge}'>{risk}</span></td>")
        print(f"</tr>")
    
    print("</table>")
    
    if missing_critical:
        print(f"<div class='critical'><strong>⚠️ CRITICAL:</strong> Missing headers: {', '.join(missing_critical)}</div>")
    
except Exception as e:
    print(f"<div class='critical'>❌ Error: {str(e)}</div>")
PYEOF

# 3. Nikto Scan
echo "<h2>3. 🔍 Web Vulnerability Scan</h2>" >> $REPORT_FILE
echo "Running Nikto scan..."
if command -v nikto &> /dev/null; then
    echo "<pre>" >> $REPORT_FILE
    timeout 120 nikto -h $TARGET_URL -Tuning 123 -Format txt -output /tmp/nikto.txt 2>&1
    cat /tmp/nikto.txt >> $REPORT_FILE 2>/dev/null
    echo "</pre>" >> $REPORT_FILE
else
    echo "<div class='warning'>⚠️ Nikto not installed</div>" >> $REPORT_FILE
fi

# 4. Common Issues Check
echo "<h2>4. ⚡ Quick Vulnerability Checks</h2>" >> $REPORT_FILE
echo "Checking common issues..."
echo "<table>" >> $REPORT_FILE
echo "<tr><th>Check</th><th>Result</th><th>Details</th></tr>" >> $REPORT_FILE

# Check robots.txt
ROBOTS=$(curl -s -o /dev/null -w "%{http_code}" $TARGET_URL/robots.txt)
if [ "$ROBOTS" == "200" ]; then
    echo "<tr><td>robots.txt</td><td><span class='badge badge-success'>Found</span></td><td>Check for sensitive paths disclosure</td></tr>" >> $REPORT_FILE
fi

# Check .git exposure
GIT=$(curl -s -o /dev/null -w "%{http_code}" $TARGET_URL/.git/config)
if [ "$GIT" == "200" ]; then
    echo "<tr><td>.git exposure</td><td><span class='badge badge-danger'>VULNERABLE</span></td><td>Git repository is exposed!</td></tr>" >> $REPORT_FILE
fi

# Server header
SERVER=$(curl -s -I $TARGET_URL | grep -i "^server:" | cut -d: -f2)
if [ ! -z "$SERVER" ]; then
    echo "<tr><td>Server Header</td><td><span class='badge badge-warning'>Exposed</span></td><td>$SERVER</td></tr>" >> $REPORT_FILE
fi

echo "</table>" >> $REPORT_FILE

# Close HTML
cat >> $REPORT_FILE << EOF
    <h2>📊 Scan Summary</h2>
    <div class="info">
        <strong>Completed:</strong> $(date)<br>
        <strong>Duration:</strong> N/A<br>
        <strong>Next Steps:</strong> Review findings and remediate critical issues
    </div>
</div>
</body>
</html>
EOF

echo "✅ Scan complete! Report: $REPORT_FILE"
echo "REPORT_FILE=$REPORT_FILE"