from fastapi import FastAPI, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
import uuid
import os
import tempfile
from func import MassScanner
import subprocess
import io
import contextlib
import traceback
from pathlib import Path
import platform
import requests
import shutil

app = FastAPI()

# Global progress storage
progress_store = {}
# Global scan data storage
scan_data_store = {}

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

@app.get("/progress/{scan_id}")
def get_progress(scan_id: str):
    return progress_store.get(scan_id, {"progress": 0, "status": "Starting..."})

@app.post("/run")
def run_scan(target: str = Form(...)):
    scan_id = str(uuid.uuid4())
    workdir = os.path.join(tempfile.gettempdir(), scan_id)
    os.makedirs(workdir, exist_ok=True)
    
    # Initialize progress
    progress_store[scan_id] = {"progress": 0, "status": "Initializing..."}

    try:
        # Step 1: Create target.txt
        progress_store[scan_id] = {"progress": 10, "status": "Creating target file..."}
        target_file = os.path.join(workdir, "target.txt")
        with open(target_file, "w", encoding='utf-8') as f:
            f.write(target.strip())
        
        # Check OS
        os_info = platform.system()
        progress_store[scan_id] = {"progress": 20, "status": "Fetching URLs from Wayback Machine..."}
        
        # Step 2: Get URLs (OS-specific)
        allurls_file = os.path.join(workdir, "allurls.txt")
        xss_file = os.path.join(workdir, "xss.txt")
        
        if os_info == "Windows":
            # Windows fallback - use Wayback Machine API
            domain = target.replace('http://', '').replace('https://', '').split('/')[0]
            api_url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=txt&fl=original&collapse=urlkey"
            
            try:
                response = requests.get(api_url, timeout=30)
                if response.status_code == 200:
                    all_urls = response.text.strip().split('\n')
                    all_urls = [url for url in all_urls if url and url.startswith('http')]
                else:
                    all_urls = []
            except:
                all_urls = []
            
            # Filter URLs manually
            progress_store[scan_id] = {"progress": 50, "status": "Filtering URLs..."}
            filtered_urls = [url for url in all_urls if url and '.js' not in url and '=' in url]
            unique_urls = list(set(filtered_urls))  # Manual deduplication
            
            # Save to xss.txt
            with open(xss_file, 'w', encoding='utf-8') as f:
                for url in unique_urls:
                    if url.strip():
                        f.write(url + '\n')
        
        else:
            # Linux - use shell commands
            cmd1 = f"cat {target_file} | waybackurls > {allurls_file}"
            result1 = subprocess.run(cmd1, shell=True, capture_output=True, text=True)
            
            if result1.returncode != 0:
                return {"status": "error", "message": f"waybackurls failed: {result1.stderr}"}
            
            if not os.path.exists(allurls_file) or os.path.getsize(allurls_file) == 0:
                return {"status": "success", "output": f"No URLs found for {target}"}
            
            # Filter and deduplicate
            progress_store[scan_id] = {"progress": 50, "status": "Filtering and deduplicating URLs..."}
            cmd2 = f"cat {allurls_file} | grep -v 'js' | grep '=' | uro > {xss_file}"
            result2 = subprocess.run(cmd2, shell=True, capture_output=True, text=True)
            
            if result2.returncode != 0:
                return {"status": "error", "message": f"Filtering failed: {result2.stderr}"}
            
            if not os.path.exists(xss_file) or os.path.getsize(xss_file) == 0:
                return {"status": "success", "output": f"No URLs with parameters found for {target}"}
            
            # Count URLs
            with open(xss_file, 'r', encoding='utf-8') as f:
                unique_urls = [line.strip() for line in f if line.strip()]
        
        unique_urls = [url for url in unique_urls if url.strip()]
        if not unique_urls:
            return {"status": "success", "output": f"No URLs with parameters found for {target}"}
        
        # Step 4: Run XSS scanner
        progress_store[scan_id] = {"progress": 70, "status": f"Scanning {len(unique_urls)} URLs for XSS vulnerabilities..."}
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
        progress_store[scan_id] = {"progress": 90, "status": "Processing results..."}
        scan_logs = log_capture.getvalue()
        # Remove ANSI color codes
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        scan_logs = ansi_escape.sub('', scan_logs)
        
        # Read results
        vulnerable_urls = ""
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, "r", encoding='utf-8') as f:
                vulnerable_urls = f.read()
        
        result = f"XSS Scan Results for {target} (OS: {os_info}):\n\n"
        result += f"Found {len(unique_urls)} URLs to test\n\n"
        if scan_logs.strip():
            result += f"Scanner Logs:\n{scan_logs}\n\n"
        if vulnerable_urls:
            result += f"Vulnerable URLs:\n{vulnerable_urls}"
        else:
            result += "No vulnerabilities found."
        
        progress_store[scan_id] = {"progress": 100, "status": "Scan completed!"}
        # Store scan data for potential cleanup
        scan_data_store[scan_id] = {
            "workdir": workdir,
            "target": target,
            "completed": True
        }
        return {"status": "success", "output": result, "scan_id": scan_id}

    except Exception as e:
        error_details = f"Error: {str(e)}\nTraceback: {traceback.format_exc()}"
        return {"status": "error", "message": error_details}

@app.delete("/cleanup/{scan_id}")
def cleanup_scan_files(scan_id: str):
    """Delete all files created during a scan"""
    try:
        if scan_id in scan_data_store:
            workdir = scan_data_store[scan_id]["workdir"]
            if os.path.exists(workdir):
                shutil.rmtree(workdir)
            # Clean up from storage
            del scan_data_store[scan_id]
            if scan_id in progress_store:
                del progress_store[scan_id]
            return {"status": "success", "message": "Scan files deleted successfully"}
        else:
            return {"status": "error", "message": "Scan ID not found"}
    except Exception as e:
        return {"status": "error", "message": f"Failed to delete files: {str(e)}"}

@app.get("/scans")
def list_scans():
    """List all completed scans"""
    completed_scans = []
    for scan_id, data in scan_data_store.items():
        if data.get("completed", False):
            completed_scans.append({
                "scan_id": scan_id,
                "target": data["target"],
                "workdir": data["workdir"]
            })
    return {"scans": completed_scans}


