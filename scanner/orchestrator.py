import subprocess
import os
import shutil
import requests
import json
import time
from datetime import datetime, timezone
from typing import TypedDict, List, Dict, Any, Tuple
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- FIX for InsecureRequestWarning ---
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# ------------------------------------

from langgraph.graph import StateGraph, END
from config.settings import settings

# --- AI & PDF Generation Dependencies ---
try:
    import google.generativeai as genai
    from fpdf import FPDF
    GEMINI_API_KEY = settings.GEMINI_API_KEY
    if GEMINI_API_KEY:
        genai.configure(api_key=GEMINI_API_KEY)
        GEMINI_AVAILABLE = True
    else:
        GEMINI_AVAILABLE = False
    PDF_AVAILABLE = True
except ImportError:
    print("[Orchestrator] WARNING: Gemini or FPDF not installed. PDF reporting will be disabled.")
    GEMINI_AVAILABLE = False
    PDF_AVAILABLE = False

try:
    from langchain_ollama import ChatOllama
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.prompts import ChatPromptTemplate
    LANGCHAIN_AVAILABLE = True
except ImportError:
    print("[Orchestrator] WARNING: LangChain/Ollama not installed. Attack path modeling will be disabled.")
    LANGCHAIN_AVAILABLE = False

# --- Helper Functions ---

def run_command(command: str, cwd: str = None) -> (bool, str):
    print(f"[Orchestrator] EXECUTING: {command.split(' ')[0]}...")
    try:
        process = subprocess.run(
            command, shell=True, check=False, capture_output=True, text=True, cwd=cwd, errors='ignore'
        )
        if process.returncode != 0:
            print(f"  -> Command failed. STDERR: {process.stderr[:500]}...")
        return process.returncode == 0, process.stdout + process.stderr
    except FileNotFoundError as e:
        print(f"  -> ERROR: Command not found: {e.filename}")
        return False, str(e)
    except Exception as e:
        print(f"  -> An unexpected error occurred: {e}")
        return False, str(e)

def is_tool_installed(name: str) -> bool:
    return shutil.which(name) is not None

def create_pdf_report(text_content: str, output_path: str):
    """
    Generates a PDF from Markdown-like text content.
    FIX: This version is more robust and handles code blocks.
    """
    if not PDF_AVAILABLE:
        print("[Orchestrator] Cannot create PDF: fpdf2 library not available.")
        return
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", size=11)
        pdf.set_auto_page_break(auto=True, margin=15)
        
        in_code_block = False
        
        for line in text_content.split('\n'):
            if line.startswith('```'):
                in_code_block = not in_code_block
                if in_code_block:
                    pdf.set_font("courier", size=9) # Use monospaced font
                    pdf.set_fill_color(240, 240, 240) # Light grey background
                else:
                    pdf.set_font("helvetica", size=11)
                pdf.ln(5)
                continue # Skip the ``` line itself

            if line.startswith('# '):
                pdf.set_font(style='B', size=20); pdf.ln(10)
                pdf.cell(0, 10, line[2:], new_x="LMARGIN", new_y="NEXT")
            elif line.startswith('## '):
                pdf.set_font(style='B', size=16); pdf.ln(8)
                pdf.cell(0, 10, line[3:], new_x="LMARGIN", new_y="NEXT")
            elif line.startswith('### '):
                pdf.set_font(style='B', size=14); pdf.ln(6)
                pdf.cell(0, 10, line[4:], new_x="LMARGIN", new_y="NEXT")
            elif line.startswith('* '):
                pdf.ln(2)
                pdf.cell(5)
                pdf.multi_cell(0, 5, f"• {line[2:]}")
            else:
                # Use multi_cell for automatic wrapping
                pdf.multi_cell(0, 5, line, fill=in_code_block)
                if not in_code_block:
                    pdf.ln(1) # Add a small gap between paragraphs

        pdf.output(output_path)
        print(f"[Orchestrator] PDF report successfully saved to: {output_path}")
    except Exception as e:
        print(f"[Orchestrator] ERROR: Failed to generate PDF report: {e}")

# --- LangGraph State Definition ---
class GraphState(TypedDict):
    job_id: str 
    profile: str
    target_url: str | None
    source_code_path: str | None
    auth_cookie: str | None 
    output_dir: str
    report_summary: List[str]
    findings: List[Dict]
    raw_reports: Dict[str, str]
    start_time: datetime

# --- Independent Scan Functions (NOW OPTIMIZED) ---

COMMON_EXCLUDES_CLI = (
    " --exclude '**/node_modules/**' "
    "--exclude '**/__pycache__/**' "
    "--exclude '**/.git/**' "
    "--exclude '**/dist/**' "
    "--exclude '**/build/**' "
    "--exclude '**/.next/**' "
    "--exclude '**/.venv/**' "
    "--exclude '**/venv/**' "
    "--exclude '**/env/**' "
    "--exclude '**/env_*/**' "
)

def run_sca_scan(src_path: str, output_dir: str) -> Dict:
    print("[SCA] Starting Dependency-Check scan...")
    if not is_tool_installed("dependency-check"):
        return {'findings': [], 'raw_report': ('SCA_DependencyCheck', 'Tool "dependency-check" not found in PATH.')}
    
    
    command = (
        f"dependency-check --scan \"{src_path}\" "
        f"--out \"{output_dir}\" --format ALL {COMMON_EXCLUDES_CLI} "
    )
    
    print(f"[SCA] Note: First scan will be slow if NVD database is not populated.")
    _, output = run_command(command)
    
    findings = []
    if "One or more dependencies were identified with critical vulnerabilities" in output:
        findings.append({'severity': 'CRITICAL', 'title': 'Vulnerable Dependencies Found', 'tool': 'SCA (Dependency-Check)', 'details': 'Critical vulnerabilities found in third-party libraries. Update immediately.'})
    elif "One or more dependencies were identified with high vulnerabilities" in output:
        findings.append({'severity': 'HIGH', 'title': 'Vulnerable Dependencies Found', 'tool': 'SCA (Dependency-Check)', 'details': 'High-severity vulnerabilities found in third-party libraries.'})
    return {'findings': findings, 'raw_report': ('SCA_DependencyCheck', output)}

def run_sast_scan(src_path: str, output_dir: str) -> Dict:
    print("[SAST] Starting Semgrep scan...")
    if not is_tool_installed("semgrep"):
        return {'findings': [], 'raw_report': ('SAST_Semgrep', 'Tool "semgrep" not found in PATH.')}

    output_file = os.path.join(output_dir, "semgrep_report.json")
    log_file = os.path.join(output_dir, "semgrep-scan.log") 
    
    # --- FIX: Use --exclude, which is the correct Semgrep flag ---
    exclude_flags = (
        "--exclude '**/node_modules/**' "
        "--exclude '**/.git/**' "
        "--exclude '**/.venv/**' "
        "--exclude '**/venv/**' "
        "--exclude '**/env/**' "
        "--exclude '**/env_*/**' "
        "--exclude '**/dist/**' "
        "--exclude '**/build/**' "
        "--exclude '**/__pycache__/**' "
        "--exclude '**/.next/**' "
    )
    command = f"semgrep scan --config auto --json -o \"{output_file}\" {exclude_flags} \"{src_path}\" {exclude_flags} --verbose \"{src_path}\" 2>&1 | tee \"{log_file}\""
    # ---------------------------------------------------------

    run_command(command)
    
    findings = []
    if os.path.exists(output_file) and os.path.getsize(output_file) > 20:
        with open(output_file, 'r') as f:
            try:
                semgrep_results = json.load(f)
                for res in semgrep_results.get('results', []):
                    severity_map = {'ERROR': 'HIGH', 'WARNING': 'MEDIUM', 'INFO': 'LOW'}
                    check_id = res.get('check_id', 'N/A')
                    path = res.get('path', 'N/A')
                    line = res.get('start', {}).get('line', 'N/A')
                    sev = severity_map.get(res.get('extra', {}).get('severity'), 'LOW')
                    findings.append({'severity': sev, 'title': f"SAST Finding: {check_id}", 'tool': 'SAST (Semgrep)', 'details': f"Issue found in {path} at line {line}."})
            except json.JSONDecodeError:
                pass
    return {'findings': findings, 'raw_report': ('SAST_Semgrep', f"Scan complete, report at {output_file}")}

def run_container_scan(src_path: str, output_dir: str) -> Dict:
    print("[CONTAINER] Starting Trivy scan...")
    if not is_tool_installed("trivy"):
        return {'findings': [], 'raw_report': ('CONTAINER_Trivy', 'Tool "trivy" not found in PATH.')}
        
    output_file = os.path.join(output_dir, "trivy_report.txt")
    log_file = os.path.join(output_dir, "trivy-scan.log") \
        
    command = (
        f"trivy fs --scanners secret,misconfig --debug -o \"{output_file}\" "
        f"--skip-dirs \"{src_path}/node_modules\" "
        f"--skip-dirs \"{src_path}/.git\" "
        f"--skip-dirs \"{src_path}/.venv\" "
        f"--skip-dirs \"{src_path}/venv\" "
        f"--skip-dirs \"{src_path}/env\" "
        f"--skip-dirs \"{src_path}/.next\" "
        f"\"{src_path}\" 2>&1 | tee \"{log_file}\""
    )
    
    print(f"[CONTAINER] Scan is running. You can monitor progress in: {log_file}")
    
    _, output = run_command(command)
    
    findings = []
    if "Total misconfigurations" in output and "Total misconfigurations: 0" not in output:
         findings.append({'severity': 'MEDIUM', 'title': 'Trivy: Misconfigurations Found', 'tool': 'CONTAINER (Trivy)', 'details': 'Trivy found misconfigurations in your project. See trivy_report.txt for details.'})
    if "Total secrets" in output and "Total secrets: 0" not in output:
         findings.append({'severity': 'CRITICAL', 'title': 'Trivy: Hardcoded Secrets Found', 'tool': 'CONTAINER (Trivy)', 'details': 'Trivy found hardcoded secrets in your project. See trivy_report.txt for details.'})
    
    return {'findings': findings, 'raw_report': ('CONTAINER_Trivy', output)}

def run_iac_scan(src_path: str, output_dir: str) -> Dict:
    print("[IAC] Starting Checkov scan...")
    if not is_tool_installed("checkov"):
        return {'findings': [], 'raw_report': ('IAC_Checkov', 'Tool "checkov" not found in PATH.')}
        
    output_file = os.path.join(output_dir, "checkov_report.json")
    
    # --- FIX: Removed buggy wildcard paths ---
    command = (
        f"checkov -d \"{src_path}\" -o json "
        f"--skip-dir node_modules "
        f"--skip-dir .git "
        f"--skip-dir .venv "
        f"--skip-dir venv "
        f"--skip-dir env "
        f"--skip-dir env_* "
        f"--skip-dir .next "
        f"| tee \"{output_file}\""
    )
    # ----------------------------------
    
    run_command(command)
    findings = []
    if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
        try:
            with open(output_file, 'r') as f:
                results = json.load(f)
                failed_checks = results.get('summary', {}).get('failed', 0)
                if failed_checks > 0:
                    findings.append({'severity': 'MEDIUM', 'title': 'IaC Misconfigurations Found', 'tool': 'IAC (Checkov)', 'details': f'{failed_checks} infrastructure-as-code misconfigurations detected.'})
        except (json.JSONDecodeError, FileNotFoundError):
             pass
    return {'findings': findings, 'raw_report': ('IAC_Checkov', f"Scan complete, report at {output_file}")}

# --- DAST Scan Functions (No changes) ---
# ... (run_resilience_check, run_nikto_scan, run_zap_scan, run_sqlmap_scan) ...
def run_resilience_check(target_url: str) -> Dict:
    # (No changes to this function)
    print("[RESILIENCE] Starting resilience checks...")
    findings = []
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.head(target_url, headers=headers, timeout=10, allow_redirects=True, verify=False)
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        cdn_indicators = {'cloudflare', 'cloudfront', 'akamai', 'fastly'}
        detected_cdn = "None"
        for key, value in resp_headers.items():
            for cdn in cdn_indicators:
                if cdn in key.lower() or cdn in value.lower():
                    detected_cdn = cdn.capitalize()
                    break
        if detected_cdn != "None":
            findings.append({'severity': 'INFO', 'title': 'CDN/WAF Detected', 'tool': 'Resilience Check', 'details': f'Application appears to be protected by {detected_cdn}.'})
        else:
            findings.append({'severity': 'MEDIUM', 'title': 'No CDN/WAF Detected', 'tool': 'Resilience Check', 'details': 'Application does not appear to be behind a known CDN or WAF.'})
    except requests.RequestException as e:
        findings.append({'severity': 'LOW', 'title': 'Resilience Check Failed', 'tool': 'Resilience Check', 'details': f'Could not perform CDN check: {e}'})
    try:
        with requests.Session() as s:
            for _ in range(15):
                if s.get(target_url, headers=headers, timeout=2, verify=False).status_code == 429:
                    findings.append({'severity': 'INFO', 'title': 'Rate Limiting Detected', 'tool': 'Resilience Check', 'details': 'Server responded with 429 (Too Many Requests).'})
                    break
            else:
                findings.append({'severity': 'LOW', 'title': 'No Rate Limiting Detected', 'tool': 'Resilience Check', 'details': 'Server did not respond with 429 to a rapid request burst.'})
    except requests.RequestException:
        pass
    return {'findings': findings, 'raw_report': ('Resilience_Check', 'Checks complete.')}

def run_nikto_scan(target_url: str, output_dir: str) -> Dict:
    # (No changes to this function)
    print("[NIKTO] Starting Nikto scan...")
    if not is_tool_installed("nikto"):
        return {'findings': [], 'raw_report': ('DAST_Nikto', 'Tool "nikto" not found in PATH.')}
    output_file = os.path.join(output_dir, "nikto_report.txt")
    ssl_flag = "-ssl" if target_url.startswith("https://") else ""
    command = f"nikto -h {target_url} -o {output_file} -Format txt {ssl_flag} -Tuning x 3 5"
    _, output = run_command(command)
    findings = []
    if "0 error(s)" not in output and "0 item(s)" not in output:
         findings.append({'severity': 'MEDIUM', 'title': 'Nikto: Server Misconfigurations Found', 'tool': 'DAST (Nikto)', 'details': 'Nikto found potential server misconfigurations or outdated software.'})
    return {'findings': findings, 'raw_report': ('DAST_Nikto', output)}
    
def run_zap_scan(target_url: str, output_dir: str, auth_cookie: str | None) -> Dict:
    print("[ZAP] Starting ZAP scan...")
    if not is_tool_installed("docker"):
        return {'findings': [], 'raw_report': ('DAST_ZAP', 'Tool "docker" not found. ZAP scan requires Docker.')}
    abs_dir = os.path.abspath(output_dir)
    report_file = "zap_report.html"
    zap_image = "ghcr.io/zaproxy/zaproxy:stable"
    
    # --- THIS IS THE UPDATE FOR STEP 4 ---
    # Base command
    command = (
        f"docker run --user 0 --rm -v \"{abs_dir}:/zap/wrk/:rw\" "
        f"{zap_image} zap-baseline.py -t {target_url} -r {report_file}"
    )
    
    # If an auth_cookie is provided, add the authentication header
    if auth_cookie:
        print("[ZAP] Running ZAP scan in AUTHENTICATED mode.")
        command += f" -H \"Cookie: {auth_cookie}\""
    else:
        print("[ZAP] Running ZAP scan in UNAUTHENTICATED mode.")
    # -------------------------------------

    _, output = run_command(command)
    findings = []
    if "FAIL-NEW" in output:
        if "High:" in output and "High: 0" not in output:
             findings.append({'severity': 'HIGH', 'title': 'ZAP High-Risk Finding', 'tool': 'DAST (ZAP)', 'details': 'ZAP identified one or more high-risk vulnerabilities (e.g., XSS, CSRF).'})
        if "Medium:" in output and "Medium: 0" not in output:
             findings.append({'severity': 'MEDIUM', 'title': 'ZAP Medium-Risk Finding', 'tool': 'DAST (ZAP)', 'details': 'ZAP identified medium-risk issues (e.g., insecure headers).'})
    return {'findings': findings, 'raw_report': ('DAST_ZAP', output)}

def run_sqlmap_scan(target_url: str, output_dir: str) -> Dict:
    # (No changes to this function)
    print("[SQLMAP] Starting SQLMap scan...")
    if not is_tool_installed("sqlmap"):
        return {'findings': [], 'raw_report': ('DAST_SQLMap', 'Tool "sqlmap" not found in PATH.')}
    if '?' not in target_url:
        return {'findings': [], 'raw_report': ('DAST_SQLMap', 'Skipped: Target URL does not contain parameters (?).')}
    command = f"sqlmap -u \"{target_url}\" --batch --level=1 --risk=1"
    _, output = run_command(command, cwd=output_dir)
    findings = []
    if "seems to be injectable" in output or "is vulnerable" in output:
        findings.append({'severity': 'CRITICAL', 'title': 'SQL Injection Confirmed', 'tool': 'DAST (SQLMap)', 'details': 'The application is vulnerable to SQL Injection.'})
    return {'findings': findings, 'raw_report': ('DAST_SQLMap', output)}

# --- LangGraph Nodes (No changes here) ---
# ... (setup_node, run_parallel_scans_node, attack_modeling_node, gemini_summarizer_node) ...
def setup_node(state: GraphState) -> GraphState:
    print(f"--- 1. SETUP (Profile: {state['profile'].upper()}) ---")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = os.path.abspath(f"scan_results/{state['job_id']}")
    os.makedirs(output_dir, exist_ok=True)
    state.update({
        'output_dir': output_dir,
        'report_summary': [f"AI-Powered Scan ({state['profile']} profile) for {state['target_url'] or state['source_code_path']} at {timestamp}"],
        'findings': [],
        'raw_reports': {}
    })
    return state

def run_parallel_scans_node(state: GraphState) -> GraphState:
    print(f"\n--- 2. PARALLEL SCAN PHASE ({state['profile'].upper()}) ---")
    profile = state['profile']
    target_url = state.get('target_url') or ""
    source_code_path = state.get('source_code_path') or ""
    
    all_jobs = {
        'sca': ("SCA", run_sca_scan, (source_code_path, state['output_dir'])),
        'sast': ("SAST", run_sast_scan, (source_code_path, state['output_dir'])),
        'container': ("CONTAINER", run_container_scan, (source_code_path, state['output_dir'])),
        'iac': ("IAC", run_iac_scan, (source_code_path, state['output_dir'])),
        'resilience': ("RESILIENCE", run_resilience_check, (target_url,)),
        'nikto': ("NIKTO", run_nikto_scan, (target_url, state['output_dir'])),
        'zap': ("ZAP", run_zap_scan, (target_url, state['output_dir'], state.get('auth_cookie'))),
        'sqlmap': ("SQLMAP", run_sqlmap_scan, (target_url, state['output_dir'])),
    }
    
    jobs_to_run = []
    if profile == 'developer':
        jobs_to_run = [all_jobs['sast'], all_jobs['sca'], all_jobs['iac'], all_jobs['container']]
    elif profile == 'web':
        if target_url:
            jobs_to_run = [all_jobs['resilience'], all_jobs['nikto'], all_jobs['zap'], all_jobs['sqlmap']]
        else:
            print("[Orchestrator] 'web' profile selected, but no target_url was provided. Skipping DAST scans.")
    elif profile == 'full':
        if source_code_path:
            jobs_to_run.extend([all_jobs['sast'], all_jobs['sca'], all_jobs['iac'], all_jobs['container']])
        if target_url:
            jobs_to_run.extend([all_jobs['resilience'], all_jobs['nikto'], all_jobs['zap'], all_jobs['sqlmap']])
            
    if not jobs_to_run:
        print("[Orchestrator] No jobs selected for the given profile and arguments. Exiting scan phase.")
        return state
    
    with ThreadPoolExecutor(max_workers=len(jobs_to_run)) as executor:
        future_to_job = {executor.submit(job, *args): name for name, job, args in jobs_to_run}
        for future in as_completed(future_to_job):
            job_name = future_to_job[future]
            try:
                result = future.result()
                if result.get('findings'): state['findings'].extend(result['findings'])
                if result.get('raw_report'):
                    tool_name, report_content = result['raw_report']
                    state['raw_reports'][tool_name] = report_content
                print(f"  -> {job_name} completed.")
            except Exception as exc:
                print(f"  -> {job_name} generated an exception: {exc}")
    
    state['report_summary'].append(f"[+] {profile.capitalize()} scan phase complete.")
    return state

def attack_modeling_node(state: GraphState) -> GraphState:
    print("\n--- 3. AI Attack Path Modeling (Ollama) ---")
    if not LANGCHAIN_AVAILABLE or not state['findings']:
        state['report_summary'].append("[-] Attack Modeling Skipped: No findings or LangChain not installed.")
        return state
    try:
        findings_for_llm = json.dumps(state['findings'], indent=2)
        prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a senior penetration tester. Analyze this JSON list of security findings. Model 1-3 plausible, step-by-step attack paths."),
            ("human", "Findings:\n{findings}")
        ])
        llm = ChatOllama(
            base_url="http://host.docker.internal:11434", 
            model="gemma:2b"
        )
        chain = prompt | llm | StrOutputParser()
        analysis = chain.invoke({"findings": findings_for_llm})
        state['raw_reports']['AI_Attack_Path_Analysis'] = analysis
        state['report_summary'].append("[+] AI Attack Path Modeling complete.")
    except Exception as e:
        print(f"[Orchestrator] ERROR: AI Attack Path Modeling failed: {e}")
        state['report_summary'].append(f"[-] AI Attack Path Modeling failed: {e}")
    return state

def gemini_summarizer_node(state: GraphState) -> Tuple[GraphState, Dict[str, Any]]:
    print("\n--- 4. AI Final Report (Gemini) ---")
    if not GEMINI_AVAILABLE:
        print("[!] Gemini API key not configured. Skipping detailed report generation.")
        return state, {}
    
    findings_summary = json.dumps(state['findings'], indent=2)
    full_context = f"## Structured Findings\n{findings_summary}\n\n## Raw Tool Outputs\n"
    for tool, report in state['raw_reports'].items():
        full_context += f"\n### {tool} Report\n"
    # --- FIX: A much better, more structured prompt ---
    prompt = f"""
    You are a Principal Application Security Engineer. Your task is to write a professional penetration test report
    based on the scan results provided below. You must also generate a structured JSON object for ticketing.

    **Scan Data:**
    {full_context}

    **Instructions:**
    First, generate a comprehensive security report in Markdown format. The report MUST be professional, clear,
    and actionable for a development team. It must include these exact sections:

    # Security Scan Report: [Target]

    ## 1. Executive Summary
    (Write a high-level overview for management. State the overall risk posture - Critical, High, Medium, or Low - based
    on the highest severity finding. Mention the total number of findings.)

    ## 2. Architectural Resilience
    (Analyze the findings from the "Resilience Check" tool. Specifically comment on whether a CDN/WAF was detected
    and if Rate Limiting is in place. Provide recommendations.)

    ## 3. Detailed Findings
    (List all findings, grouped by severity from CRITICAL down to INFO. For each finding,
    you MUST include:
    * **Title:** The `title` from the finding.
    * **Severity:** The `severity`.
    * **Tool:** The `tool` that found it.
    * **Description:** The `details` from the finding.
    * **Location:** The `location` (if available).
    * **Remediation:** The `remediation` (if provided), otherwise, provide a general best-practice fix.
    )

    ## 4. Prioritized Remediation Plan
    (Create a short, prioritized list of the top 3-5 actions the development team must take,
    starting with the most critical findings.)
    
    ---TICKETING-JSON---
    
    After this token, provide a JSON array of ticket objects for all 'CRITICAL' and 'HIGH' severity findings.
    Each object must have this exact format:
    {{
      "title": "Vulnerability Title",
      "priority": "Critical" or "High",
      "description": "A detailed description of the issue, the risk, and the exact location (e..g., file path, URL).",
      "remediation": "A step-by-step guide on how to fix the vulnerability."
    }}
    """
    
    gemini_response = ""
    ticketing_json = []
    try:
        model = genai.GenerativeModel('gemini-2.5-flash')
        
        response = model.generate_content(prompt)
        gemini_response = response.text
        
        if "---TICKETING-JSON---" in gemini_response:
            parts = gemini_response.split("---TICKETING-JSON---")
            markdown_report = parts[0]
            try:
                # Find the start of the JSON array
                json_start = parts[1].find('[')
                json_end = parts[1].rfind(']') + 1
                json_str = parts[1][json_start:json_end]
                ticketing_json = json.loads(json_str)
            except json.JSONDecodeError as json_err:
                print(f"[Orchestrator] ERROR: Gemini produced invalid JSON for ticketing: {json_err}")
                markdown_report = f"{markdown_report}\n\n[ERROR] Failed to parse ticketing JSON from AI."
        else:
            markdown_report = gemini_response

        report_md_path = os.path.join(state['output_dir'], "Gemini_Security_Report.md")
        report_pdf_path = os.path.join(state['output_dir'], "Gemini_Security_Report.pdf")
        with open(report_md_path, 'w') as f: f.write(markdown_report)
        create_pdf_report(markdown_report, report_pdf_path)
        state['report_summary'].append(f"[+] Gemini Report and PDF generated in {state['output_dir']}.")
    except Exception as e:
        print(f"[Orchestrator] ERROR: Failed to generate report with Gemini: {e}")
        state['report_summary'].append(f"[-] Gemini Report generation failed: {e}")
    
    return state, ticketing_json

# --- Main Entrypoint Function ---

def run_orchestration(job_id: str, profile: str, target_url: str | None, source_code_path: str | None, auth_cookie: str | None = None) -> Dict[str, Any]:
    """
    This is the main entry point called by the Celery task.
    """
    
    workflow = StateGraph(GraphState) 
    workflow.set_entry_point("setup")
    workflow.add_node("setup", setup_node)
    workflow.add_node("parallel_scans", run_parallel_scans_node)
    workflow.add_node("attack_modeling", attack_modeling_node)
    
    start_time = datetime.now(timezone.utc)
    
    def gemini_node_wrapper(state: GraphState):
        new_state, ticketing_data = gemini_summarizer_node(state)
        if ticketing_data:
            print(f"[Orchestrator] Generated {len(ticketing_data)} tickets for JIRA.")
        return new_state

    workflow.add_node("gemini_summarizer", gemini_node_wrapper)
    workflow.add_edge("setup", "parallel_scans")
    workflow.add_edge("parallel_scans", "attack_modeling")
    workflow.add_edge("attack_modeling", "gemini_summarizer")
    workflow.add_edge("gemini_summarizer", END)
    
    app = workflow.compile()
    
    initial_state = GraphState(
        job_id=job_id,
        profile=profile,
        target_url=target_url,
        source_code_path=source_code_path,
        auth_cookie=auth_cookie,
        output_dir="", 
        report_summary=[],
        findings=[],
        raw_reports={},
        start_time=start_time
    )
    
    final_state = app.invoke(initial_state)
    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in final_state['findings']:
        sev = f.get('severity', 'INFO')
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "status": "COMPLETED",
        "output_dir": final_state['output_dir'],
        "findings_summary": severity_counts,
        "report_url": os.path.join(final_state['output_dir'], "Gemini_Security_Report.pdf"),
        "findings": final_state['findings'],
        "start_time": start_time.isoformat()
    }