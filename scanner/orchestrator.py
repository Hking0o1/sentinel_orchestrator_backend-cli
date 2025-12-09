"""
Ultra-Optimized Orchestrator with Correlation Engine
"""
import os
import json
import logging
from datetime import datetime, timezone
from typing import TypedDict, List, Dict, Any, Tuple, Optional
from concurrent.futures import ProcessPoolExecutor, as_completed

# --- Import our modularized tools ---
from scanner.tools import (
    run_sca_scan,
    run_sast_scan,
    run_container_scan,
    run_iac_scan,
    run_resilience_check,
    run_nikto_scan,
    run_zap_scan,
    run_sqlmap_scan
)
from scanner.tools.utils import get_logger, normalize_severity

# --- Import Correlation Engine ---
from scanner.correlation.engine import CorrelationEngine

from langgraph.graph import StateGraph, END
from config.settings import settings

# --- Setup Logger ---
logger = get_logger("orchestrator")

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
    logger.warning("Gemini or FPDF not installed. Reporting features limited.")
    GEMINI_AVAILABLE = False
    PDF_AVAILABLE = False

try:
    from langchain_ollama import ChatOllama
    from langchain_core.output_parsers import StrOutputParser
    from langchain_core.prompts import ChatPromptTemplate
    LANGCHAIN_AVAILABLE = True
except ImportError:
    logger.warning("LangChain/Ollama not installed. Attack path modeling disabled.")
    LANGCHAIN_AVAILABLE = False


# --- Helper Functions ---

def safe_path(path: str) -> str:
    """Sanitizes a file path."""
    if not path: return ""
    return os.path.abspath(str(path))

def mask_secret(s: Optional[str]) -> str:
    """Masks secrets for logging."""
    if not s: return ""
    if len(s) <= 6: return "****"
    return s[:3] + "..." + s[-3:]

def sanitize_text_for_pdf(text: str) -> str:
    """
    Replaces characters that are not supported by the standard FPDF fonts (Latin-1).
    """
    replacements = {
        "•": "-",
        "–": "-",
        "—": "-",
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "…": "...",
    }
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    # Fallback: force encode to latin-1, replacing unknown chars with '?'
    return text.encode('latin-1', 'replace').decode('latin-1')

def create_pdf_report(text_content: str, output_path: str):
    """Generates a PDF from Markdown-like text content."""
    if not PDF_AVAILABLE: return
    try:
        pdf = FPDF()
        pdf.add_page()
        try:
            pdf.set_font("helvetica", size=11)
        except Exception:
            pdf.set_font("Arial", size=11)
            
        pdf.set_auto_page_break(auto=True, margin=15)
        in_code_block = False
        
        # Pre-process text to remove unsupported characters
        safe_content = sanitize_text_for_pdf(text_content)
        
        for line in safe_content.split('\n'):
            if line.startswith('```'):
                in_code_block = not in_code_block
                if in_code_block:
                    pdf.set_font("courier", size=9)
                    pdf.set_fill_color(240, 240, 240)
                else:
                    pdf.set_font("helvetica", size=11)
                pdf.ln(5)
                continue

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
                # FIX: Use hyphen instead of bullet to avoid unicode errors
                pdf.ln(2); pdf.cell(5)
                pdf.multi_cell(0, 5, f"- {line[2:]}")
            else:
                pdf.multi_cell(0, 5, line, fill=in_code_block)
                if not in_code_block: pdf.ln(1)
        
        pdf.output(output_path)
        logger.info(f"PDF report saved to: {output_path}")
    except Exception as e:
        logger.error(f"Failed to generate PDF report: {e}")


# --- LangGraph State Definition ---
class GraphState(TypedDict):
    job_id: str 
    profile: str
    target_url: Optional[str]
    source_code_path: Optional[str]
    auth_cookie: Optional[str]
    output_dir: str
    report_summary: List[str]
    findings: List[Dict[str, Any]]
    raw_reports: Dict[str, Any]
    start_time: datetime


# --- Nodes ---

def setup_node(state: GraphState) -> GraphState:
    logger.info(f"--- SETUP (Job: {state['job_id']}, Profile: {state['profile'].upper()}) ---")
    # Ensure output directory exists
    output_dir = safe_path(f"scan_results/{state['job_id']}")
    os.makedirs(output_dir, exist_ok=True)
    
    state.update({
        'output_dir': output_dir,
        'report_summary': [f"Scan started for {state['target_url'] or state['source_code_path']}"],
        'findings': [],
        'raw_reports': {}
    })
    return state

def run_parallel_scans_node(state: GraphState) -> GraphState:
    logger.info(f"--- PARALLEL SCAN PHASE ---")
    profile = state['profile']
    target_url = state.get('target_url')
    source_code_path = state.get('source_code_path')
    output_dir = state['output_dir']
    auth_cookie = state.get('auth_cookie')

    # Map job names to their functions and arguments
    all_jobs = {
        'sca': (run_sca_scan, (source_code_path, output_dir)),
        'sast': (run_sast_scan, (source_code_path, output_dir)),
        'container': (run_container_scan, (source_code_path, output_dir)),
        'iac': (run_iac_scan, (source_code_path, output_dir)),
        'resilience': (run_resilience_check, (target_url,)),
        'nikto': (run_nikto_scan, (target_url, output_dir)),
        'zap': (run_zap_scan, (target_url, output_dir, auth_cookie)),
        'sqlmap': (run_sqlmap_scan, (target_url, output_dir)),
    }
    
    jobs_to_run = []
    if profile == 'developer':
        jobs_to_run = ['sast', 'sca', 'iac', 'container']
    elif profile == 'web':
        if target_url:
            jobs_to_run = ['resilience', 'nikto', 'zap', 'sqlmap']
        else:
            logger.warning("Web profile selected but no target_url provided.")
    elif profile == 'full':
        if source_code_path:
            jobs_to_run.extend(['sast', 'sca', 'iac', 'container'])
        if target_url:
            jobs_to_run.extend(['resilience', 'nikto', 'zap', 'sqlmap'])

    if not jobs_to_run:
        return state

    # Use ProcessPoolExecutor for true parallelism
    max_workers = min(len(jobs_to_run), int(os.getenv("MAX_WORKERS", 8)))
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        future_to_job = {}
        for name in jobs_to_run:
            if name in all_jobs:
                func, args = all_jobs[name]
                
                # Check 1: Do we have the required arguments?
                if 'sca' in name or 'sast' in name or 'iac' in name or 'container' in name:
                    if not args[0]: 
                        logger.warning(f"Skipping {name}: No source code path provided.")
                        continue 
                    
                    # Check 2: Does the path exist? (FIX for "Path does not exist" error)
                    if not os.path.exists(args[0]):
                        logger.error(f"Skipping {name}: Path does not exist inside container: {args[0]}")
                        state['report_summary'].append(f"Skipped {name}: Path not found: {args[0]}")
                        continue
                
                future = executor.submit(func, *args)
                future_to_job[future] = name

        for future in as_completed(future_to_job):
            job_name = future_to_job[future]
            try:
                result = future.result()
                new_findings = result.get('findings', [])
                if new_findings:
                    state['findings'].extend(new_findings)
                
                raw_report = result.get('raw_report')
                if raw_report:
                    label, content = raw_report
                    state['raw_reports'][label] = str(content)

                logger.info(f"Job {job_name} finished. Found {len(new_findings)} issues.")
            except Exception as exc:
                logger.error(f"Job {job_name} failed: {exc}")
                state['report_summary'].append(f"Job {job_name} failed: {exc}")

    state['report_summary'].append(f"Parallel scans complete. Raw findings: {len(state['findings'])}")
    return state

def correlation_node(state: GraphState) -> GraphState:
    logger.info("--- CORRELATION ENGINE ---")
    if not state['findings']: return state
    try:
        engine = CorrelationEngine()
        engine.ingest_standard_findings(state['findings'])
        correlated = engine.run()
        state['findings'] = [f.model_dump() for f in correlated]
        logger.info(f"Correlation complete. Consolidated to {len(state['findings'])} findings.")
        state['report_summary'].append(f"Correlation Engine: Consolidated to {len(state['findings'])} findings.")
    except Exception as e:
        logger.error(f"Correlation failed: {e}")
        state['report_summary'].append(f"Correlation Engine failed: {e}")
    return state

def attack_modeling_node(state: GraphState) -> GraphState:
    logger.info("--- AI ATTACK PATH MODELING ---")
    if not LANGCHAIN_AVAILABLE or not state['findings']:
        return state

    try:
        # We summarize findings to avoid hitting token limits
        summary_for_ai = []
        for f in state['findings']:
            if f.get('severity') in ['CRITICAL', 'HIGH']:
                summary_for_ai.append(f"{f.get('severity')}: {f.get('title')} ({f.get('tool_source')})")
        
        if not summary_for_ai:
             summary_for_ai = [f"{f.get('severity')}: {f.get('title')}" for f in state['findings'][:10]]

        findings_json = json.dumps(summary_for_ai, indent=2)
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", "You are a senior penetration tester. Analyze these security findings. Model 1-3 plausible, step-by-step attack paths an attacker could take to compromise the system."),
            ("human", "Findings:\n{findings}")
        ])
        
        llm = ChatOllama(
            base_url="[http://host.docker.internal:11434](http://host.docker.internal:11434)", 
            model="gemma:2b"
        )
        
        chain = prompt | llm | StrOutputParser()
        analysis = chain.invoke({"findings": findings_json})
        
        state['raw_reports']['AI_Attack_Path_Analysis'] = analysis
        state['report_summary'].append("AI Attack Path Modeling complete.")
        
    except Exception as e:
        logger.error(f"AI Attack Modeling failed: {e}")
        
    return state

def gemini_summarizer_node(state: GraphState) -> Tuple[GraphState, List[Dict[str, Any]]]:
    logger.info("--- AI FINAL REPORT (GEMINI) ---")
    if not GEMINI_AVAILABLE:
        logger.warning("Gemini API key not configured.")
        return state, []

    # Prepare context
    findings_summary = json.dumps(state['findings'][:50], indent=2, default=str) 
    
    prompt = f"""
    You are a Principal Application Security Engineer. Write a professional penetration test report based on these findings.
    
    **Scan Data:**
    {findings_summary}

    **Instructions:**
    1. Generate a Markdown report with: Executive Summary, detailed findings grouped by severity, and a prioritized remediation plan.
    2. After the report, add the separator ---TICKETING-JSON---
    3. Then provide a JSON array of tickets for CRITICAL/HIGH issues. Format: {{ "title": "...", "priority": "...", "description": "...", "remediation": "..." }}
    """
    
    ticketing_json = []
    try:
        model = genai.GenerativeModel('gemini-2.5-flash') 
        response = model.generate_content(prompt)
        gemini_response = response.text
        
        markdown_report = gemini_response
        if "---TICKETING-JSON---" in gemini_response:
            parts = gemini_response.split("---TICKETING-JSON---")
            markdown_report = parts[0]
            try:
                json_str = parts[1].strip()
                if json_str.startswith("```json"):
                    json_str = json_str[7:]
                elif json_str.startswith("```"):
                    json_str = json_str[3:]
                
                if json_str.endswith("```"):
                    json_str = json_str[:-3]
                
                json_str = json_str.strip() 
                ticketing_json = json.loads(json_str)
            except json.JSONDecodeError:
                logger.error("Failed to parse ticketing JSON.")

        # Store markdown for frontend use
        state['raw_reports']['AI_Report_Text'] = markdown_report

        md_path = os.path.join(state['output_dir'], "Gemini_Security_Report.md")
        pdf_path = os.path.join(state['output_dir'], "Gemini_Security_Report.pdf")
        
        with open(md_path, 'w', encoding='utf-8') as f: f.write(markdown_report)
        create_pdf_report(markdown_report, pdf_path)
        state['report_summary'].append(f"Gemini Report saved to {md_path}")
        
    except Exception as e:
        logger.error(f"Gemini Report Generation failed: {e}")
    
    return state, ticketing_json

# --- Main Entrypoint ---
def run_orchestration(job_id: str, profile: str, target_url: Optional[str], source_code_path: Optional[str], auth_cookie: Optional[str] = None) -> Dict[str, Any]:
    logger.info(f"Orchestration START job={job_id}")
    
    workflow = StateGraph(GraphState)
    workflow.set_entry_point("setup")
    workflow.add_node("setup", setup_node)
    workflow.add_node("parallel_scans", run_parallel_scans_node)
    workflow.add_node("correlation", correlation_node)
    workflow.add_node("attack_modeling", attack_modeling_node)
    
    def gemini_node_wrapper(state: GraphState):
        new_state, ticketing_data = gemini_summarizer_node(state)
        if ticketing_data:
             with open(os.path.join(new_state['output_dir'], 'tickets.json'), 'w') as f:
                json.dump(ticketing_data, f, indent=2)
        return new_state

    workflow.add_node("gemini_summarizer", gemini_node_wrapper)
    
    workflow.add_edge("setup", "parallel_scans")
    workflow.add_edge("parallel_scans", "correlation")
    workflow.add_edge("correlation", "attack_modeling")
    workflow.add_edge("attack_modeling", "gemini_summarizer")
    workflow.add_edge("gemini_summarizer", END)
    
    app = workflow.compile()
    
    start_time = datetime.now(timezone.utc)
    initial_state = GraphState(
        job_id=job_id, profile=profile, target_url=target_url,
        source_code_path=source_code_path, auth_cookie=auth_cookie,
        output_dir="", report_summary=[], findings=[], raw_reports={},
        start_time=start_time
    )
    
    final_state = app.invoke(initial_state)

    try:
        findings_to_save = final_state.get('findings', [])
        if findings_to_save:
            thread = threading.Thread(
                target=data_sanitizer.process_and_save, 
                args=(findings_to_save,),
                daemon=True # Daemon threads die if the main process dies
            )
            thread.start()
            logger.info("Triggered background data sanitization task.")
    except Exception as e:
        logger.error(f"Failed to start data pipeline thread: {e}")
    
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in final_state.get('findings', []):
        sev = normalize_severity(f.get('severity'))
        if sev in severity_counts: severity_counts[sev] += 1
            
    return {
        "status": "COMPLETED",
        "output_dir": final_state['output_dir'],
        "findings_summary": severity_counts,
        "report_url": os.path.join(final_state['output_dir'], "Gemini_Security_Report.pdf"),
        "findings": final_state['findings'],
        "start_time": start_time.isoformat(),
        "end_time": datetime.now(timezone.utc).isoformat()
    }
  
# -------------------------
# CLI for local testing
# -------------------------
if __name__ == "__main__":
    import argparse
    # Setup console logging for local run
    logging.getLogger().setLevel(logging.DEBUG)
    
    parser = argparse.ArgumentParser(description="Run sentinel orchestrator locally")
    parser.add_argument("--job-id", default=f"local-{int(datetime.now().timestamp())}")
    parser.add_argument("--profile", default="developer")
    parser.add_argument("--target", default=None)
    parser.add_argument("--src", default=".")
    parser.add_argument("--cookie", default=None)
    
    args = parser.parse_args()
    
    print(f"--- Starting Local Scan: {args.job_id} ---")
    out = run_orchestration(args.job_id, args.profile, args.target, args.src, args.cookie)
    print(json.dumps(out, indent=2, default=str))