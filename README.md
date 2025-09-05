# XSS Security Scanner

A professional web-based XSS vulnerability scanner with modern UI and comprehensive security testing capabilities.

## Features

- 🛡️ **Professional XSS Detection**: Uses industry-standard tools and techniques
- 🌐 **Web-based Interface**: Modern, responsive design for easy access
- ⚡ **Fast Scanning**: Concurrent processing with configurable parameters
- 🔍 **Comprehensive Coverage**: Integrates waybackurls, uro, and custom payloads
- 📊 **Detailed Reports**: Real-time scan progress and vulnerability reporting

## Tools Integration

- **waybackurls**: Historical URL discovery from Wayback Machine
- **uro**: URL deduplication and filtering
- **Custom XSS Scanner**: High-performance async scanner with custom payloads

## Installation

### Local Development

1. Clone the repository:
```bash
git clone https://github.com/yourusername/xss-scanner.git
cd xss-scanner
```

2. Install dependencies:
```bash
# Install Go tools
go install github.com/tomnomnom/waybackurls@latest
go install github.com/s0md3v/uro@latest

# Install Python dependencies
cd backend
pip install -r requirements.txt
```

3. Run the application:
```bash
uvicorn main:app --reload --port 8000
```

### Docker Deployment

```bash
docker build -t xss-scanner .
docker run -p 8000:8000 xss-scanner
```

## Usage

1. Open your browser and navigate to `http://localhost:8000`
2. Enter a target domain (e.g., `example.com`)
3. Click "Start Scan" to begin the security assessment
4. View real-time results and vulnerability reports

## Workflow

1. **URL Discovery**: `cat target.txt | waybackurls > allurls.txt`
2. **Filtering**: `cat allurls.txt | grep -v 'js' | grep '=' | uro > xss.txt`
3. **XSS Testing**: `python3 MXS.py -i xss.txt -p xss_payloads.txt -c 1500 -t 15`

## Configuration

- **Concurrency**: Adjust scanning speed (default: 1500)
- **Timeout**: Request timeout in seconds (default: 15)
- **Payloads**: Customize XSS payloads in `xss_payloads.txt`

## Security Notice

This tool is for authorized security testing only. Only scan domains you own or have explicit permission to test.

## License

MIT License - See LICENSE file for details