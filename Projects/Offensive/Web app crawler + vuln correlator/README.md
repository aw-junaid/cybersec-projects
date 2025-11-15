# Web App Crawler + Vulnerability Correlator - Find Attack Paths

## How to Run the Code

### Python Version
```bash
# Install dependencies
pip install requests beautifulsoup4 networkx matplotlib

# Basic scan
python web_crawler.py https://example.com

# With custom parameters
python web_crawler.py https://example.com --threads 20 --max-pages 1000

# Skip vulnerability scanning (crawl only)
python web_crawler.py https://example.com --no-scan

# Custom output file
python web_crawler.py https://example.com --output my_scan_report.json
```

### C Version
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install libcurl4-openssl-dev

# Compile the C program
gcc -o web_crawler web_crawler.c -lcurl -lpthread

# Run basic crawl
./web_crawler https://example.com
```

## Algorithm Explanation

### Web Crawling Algorithm:

**1. URL Discovery:**
```
1. Start with seed URLs
2. Extract links from HTML using regex/parsing
3. Normalize URLs (absolute vs relative)
4. Filter by domain scope
5. Add to crawl queue with depth tracking
```

**2. Polite Crawling:**
```
1. Respect robots.txt
2. Implement rate limiting
3. Use proper User-Agent headers
4. Handle redirects appropriately
5. Manage session cookies
```

**3. Content Analysis:**
```
1. Parse HTML structure
2. Extract forms and input fields
3. Identify JavaScript endpoints
4. Analyze response headers
5. Detect sensitive information
```
