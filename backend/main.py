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
        
        # Step 2: cat target.txt | waybackurls > allurls.txt
        allurls_file = os.path.join(workdir, "allurls.txt")
        cmd1 = f"cat {target_file} | waybackurls > {allurls_file}"
        result1 = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
        
        if result1.returncode != 0:
            return {"status": "error", "message": f"waybackurls failed: {result1.stderr}"}
        
        # Check if allurls.txt has content
        if not os.path.exists(allurls_file) or os.path.getsize(allurls_file) == 0:
            return {"status": "success", "output": f"No URLs found by waybackurls for {target}"}
        
        # Step 3: cat allurls.txt | grep -v 'js' | grep '=' | uro > xss.txt
        xss_file = os.path.join(workdir, "xss.txt")
        cmd2 = f"cat {allurls_file} | grep -v 'js' | grep '=' | uro > {xss_file}"
        result2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True)
        
        if result2.returncode != 0:
            return {"status": "error", "message": f"Filtering/uro failed: {result2.stderr}"}
        
        # Check if xss.txt has content
        if not os.path.exists(xss_file) or os.path.getsize(xss_file) == 0:
            return {"status": "success", "output": f"No URLs with parameters found for {target}"}
        
        # Count URLs for reporting
        with open(xss_file, 'r') as f:
            unique_urls = [line.strip() for line in f if line.strip()]
        
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


