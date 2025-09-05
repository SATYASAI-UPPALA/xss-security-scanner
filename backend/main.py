from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uuid
import os
import tempfile
import requests
from func import MassScanner
from urllib.parse import urljoin, urlparse
import re
import subprocess
import sys
import io
import contextlib
import traceback
from pathlib import Path

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    # Handle both local and container paths
    frontend_path = Path("../frontend/index.html")
    if not frontend_path.exists():
        frontend_path = Path("/app/frontend/index.html")
    return FileResponse(str(frontend_path))

@app.post("/run")
def run_scan(target: str = Form(...)):
    scan_id = str(uuid.uuid4())
    workdir = os.path.join(tempfile.gettempdir(), scan_id)
    os.makedirs(workdir, exist_ok=True)

    try:
        # Step 1: Create target.txt
        target_file = os.path.join(workdir, "target.txt")
        with open(target_file, "w") as f:
            f.write(target.strip())
        
        # Step 2: waybackurls
        allurls_file = os.path.join(workdir, "allurls.txt")
        with open(target_file, 'r') as f:
            target_content = f.read().strip()
        
        # Run waybackurls
        result1 = subprocess.run(
            ['/go/bin/waybackurls'], 
            input=target_content, 
            text=True, 
            capture_output=True
        )
        
        if result1.returncode != 0:
            return {"status": "error", "message": f"waybackurls failed: {result1.stderr}"}
        
        # Save waybackurls output
        with open(allurls_file, 'w') as f:
            f.write(result1.stdout)
        
        if not result1.stdout.strip():
            return {"status": "success", "output": f"No URLs found by waybackurls for {target}"}
        
        # Step 3: Filter and deduplicate
        urls = result1.stdout.strip().split('\n')
        filtered_urls = [url for url in urls if url and '.js' not in url and '=' in url]
        
        if not filtered_urls:
            return {"status": "success", "output": f"No URLs with parameters found for {target}"}
        
        # Run uro for deduplication
        uro_input = '\n'.join(filtered_urls)
        result2 = subprocess.run(
            ['uro'], 
            input=uro_input, 
            text=True, 
            capture_output=True
        )
        
        xss_file = os.path.join(workdir, "xss.txt")
        if result2.returncode == 0:
            with open(xss_file, 'w') as f:
                f.write(result2.stdout)
            unique_urls = result2.stdout.strip().split('\n')
        else:
            # Fallback: manual deduplication
            unique_urls = list(set(filtered_urls))
            with open(xss_file, 'w') as f:
                for url in unique_urls:
                    f.write(url + '\n')
        
        unique_urls = [url for url in unique_urls if url.strip()]
        if not unique_urls:
            return {"status": "success", "output": f"No URLs with parameters found for {target}"}
        
        # Step 4: python3 MXS.py -i xss.txt -p xss_payloads.txt -c 1500 -t 15
        output_file = os.path.join(workdir, "results.txt")
        
        # Capture all output from scanner
        log_capture = io.StringIO()
        try:
            with contextlib.redirect_stdout(log_capture), contextlib.redirect_stderr(log_capture):
                scanner = MassScanner(xss_file, output_file, 1500, 15, "xss_payloads.txt")
                scanner.run()
        except Exception as scan_error:
            log_capture.write(f"\nScanner Error: {str(scan_error)}\n")
            log_capture.write(f"Traceback: {traceback.format_exc()}\n")
        
        # Get captured logs and clean ANSI codes
        scan_logs = log_capture.getvalue()
        # Remove ANSI color codes
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        scan_logs = ansi_escape.sub('', scan_logs)
        
        # Read results
        vulnerable_urls = ""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, "r") as f:
                vulnerable_urls = f.read()
        
        result = f"XSS Scan Results for {target}:\n\n"
        result += f"Found {len(unique_urls)} URLs to test\n\n"
        if scan_logs.strip():
            result += f"Scanner Logs:\n{scan_logs}\n\n"
        if vulnerable_urls:
            result += f"Vulnerable URLs:\n{vulnerable_urls}"
        else:
            result += "No vulnerabilities found."
        
        return {"status": "success", "output": result}

    except Exception as e:
        error_details = f"Error: {str(e)}\nTraceback: {traceback.format_exc()}"
        return {"status": "error", "message": error_details}


