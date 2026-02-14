"""
Web Application Security Tester - Streamlit Version
A modern, user-friendly security testing tool using Requests, Selenium, and Burp Suite integration.
"""

import streamlit as st
import json
import os
import sys
from datetime import datetime

# Add core to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.scanner import SecurityScanner
from core.report_generator import ReportGenerator

# Page configuration
st.set_page_config(
    page_title="Web App Security Tester",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for modern styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    
    * {
        font-family: 'Inter', sans-serif !important;
    }
    
    .main {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
    }
    
    .stApp {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    
    /* Header styling */
    .header-container {
        text-align: center;
        padding: 40px 20px;
        background: linear-gradient(135deg, rgba(255,255,255,0.15) 0%, rgba(255,255,255,0.05) 100%);
        border-radius: 20px;
        margin-bottom: 30px;
        border: 1px solid rgba(255,255,255,0.2);
        backdrop-filter: blur(10px);
    }
    
    .header-title {
        color: white;
        font-size: 2.5rem;
        font-weight: 800;
        margin-bottom: 10px;
        text-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .header-subtitle {
        color: rgba(255,255,255,0.9);
        font-size: 1.1rem;
        font-weight: 500;
    }
    
    /* Card styling */
    .glass-card {
        background: rgba(255, 255, 255, 0.95);
        border-radius: 20px;
        padding: 25px;
        margin-bottom: 20px;
        border: 1px solid rgba(255, 255, 255, 0.3);
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
    }
    
    /* Section headers */
    .section-header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 20px;
        padding-bottom: 15px;
        border-bottom: 2px solid #e0e7ff;
    }
    
    .section-number {
        width: 36px;
        height: 36px;
        background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%);
        color: white;
        border-radius: 12px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        font-size: 16px;
    }
    
    .section-title {
        font-size: 1.3rem;
        font-weight: 700;
        color: #1e293b;
    }
    
    /* Input styling */
    .stTextInput > div > div > input {
        border-radius: 12px !important;
        border: 2px solid #e2e8f0 !important;
        padding: 12px 16px !important;
        font-size: 16px !important;
        background: white !important;
    }
    
    .stTextInput > div > div > input:focus {
        border-color: #6366f1 !important;
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1) !important;
    }
    
    /* Button styling */
    .stButton > button {
        background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%) !important;
        color: white !important;
        border: none !important;
        padding: 16px 40px !important;
        font-size: 1.1rem !important;
        font-weight: 700 !important;
        border-radius: 14px !important;
        width: 100% !important;
        box-shadow: 0 10px 30px rgba(99, 102, 241, 0.4) !important;
        transition: all 0.3s ease !important;
    }
    
    .stButton > button:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 15px 40px rgba(99, 102, 241, 0.5) !important;
    }
    
    /* Checkbox styling */
    .stCheckbox > label {
        font-weight: 600 !important;
        color: #1e293b !important;
    }
    
    /* Progress bar */
    .stProgress > div > div > div > div {
        background: linear-gradient(90deg, #6366f1, #4f46e5) !important;
    }
    
    /* Status badges */
    .badge {
        display: inline-block;
        padding: 6px 14px;
        border-radius: 20px;
        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
    }
    
    .badge-critical { background: #ef4444; color: white; }
    .badge-high { background: #f97316; color: white; }
    .badge-medium { background: #eab308; color: white; }
    .badge-low { background: #22c55e; color: white; }
    .badge-info { background: #3b82f6; color: white; }
    
    /* Finding cards */
    .finding-card {
        border-radius: 16px;
        padding: 20px;
        margin-bottom: 15px;
        border-left: 4px solid;
        background: #f8fafc;
    }
    
    .finding-critical { border-left-color: #ef4444; background: #fef2f2; }
    .finding-high { border-left-color: #f97316; background: #fff7ed; }
    .finding-medium { border-left-color: #eab308; background: #fefce8; }
    .finding-low { border-left-color: #22c55e; background: #f0fdf4; }
    .finding-info { border-left-color: #3b82f6; background: #eff6ff; }
    
    /* Stats grid */
    .stat-box {
        text-align: center;
        padding: 20px;
        border-radius: 16px;
        border: 2px solid transparent;
    }
    
    .stat-critical { background: #fef2f2; border-color: #fecaca; }
    .stat-high { background: #fff7ed; border-color: #fed7aa; }
    .stat-medium { background: #fefce8; border-color: #fde047; }
    .stat-low { background: #f0fdf4; border-color: #86efac; }
    .stat-info { background: #eff6ff; border-color: #93c5fd; }
    
    .stat-number {
        font-size: 2.5rem;
        font-weight: 800;
        line-height: 1;
    }
    
    .stat-label {
        font-size: 0.9rem;
        color: #64748b;
        margin-top: 8px;
        font-weight: 600;
    }
    
    /* History items */
    .history-item {
        padding: 16px 20px;
        background: #f8fafc;
        border-radius: 12px;
        margin-bottom: 10px;
        border: 1px solid #e2e8f0;
    }
    
    /* Empty state */
    .empty-state {
        text-align: center;
        padding: 40px;
        color: #94a3b8;
    }
    
    /* Dark mode adjustments */
    @media (prefers-color-scheme: dark) {
        .glass-card {
            background: rgba(30, 41, 59, 0.95);
            border-color: rgba(255, 255, 255, 0.1);
        }
        
        .section-title {
            color: #f1f5f9;
        }
        
        .history-item {
            background: #1e293b;
            border-color: #334155;
        }
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'scanner' not in st.session_state:
    st.session_state.scanner = SecurityScanner()
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'current_scan_id' not in st.session_state:
    st.session_state.current_scan_id = None
if 'is_scanning' not in st.session_state:
    st.session_state.is_scanning = False

# Ensure directories exist
os.makedirs('reports', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# Header
st.markdown("""
<div class="header-container">
    <h1 class="header-title">🛡️ Web App Security Tester</h1>
    <p class="header-subtitle">Advanced vulnerability scanner powered by Requests, Selenium & Burp Suite</p>
</div>
""", unsafe_allow_html=True)

# Main content container
with st.container():
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    # Step 1: Target URL
    st.markdown("""
    <div class="section-header">
        <div class="section-number">1</div>
        <div class="section-title">Enter Target URL</div>
    </div>
    """, unsafe_allow_html=True)
    
    target_url = st.text_input(
        "Target URL",
        value="http://testphp.vulnweb.com",
        placeholder="https://example.com",
        label_visibility="collapsed"
    )
    
    st.caption("💡 Enter the full URL including http:// or https:// protocol")
    st.markdown('</div>', unsafe_allow_html=True)

# Step 2: Scan Options
with st.container():
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown("""
    <div class="section-header">
        <div class="section-number">2</div>
        <div class="section-title">Select Scan Modules</div>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        check_recon = st.checkbox("🔍 **Reconnaissance**", value=True, 
                                  help="Detect server info, security headers, technology stack")
        st.caption("Detect server info, security headers, technology stack")
        
        check_vuln = st.checkbox("🐛 **Vulnerability Scan**", value=True,
                                help="Test for XSS, SQL Injection, CSRF, Open Redirect")
        st.caption("Test for XSS, SQL Injection, CSRF, Open Redirect")
    
    with col2:
        check_browser = st.checkbox("🌐 **Browser Automation**", value=True,
                                   help="DOM XSS, mixed content, client-side storage tests")
        st.caption("DOM XSS, mixed content, client-side storage tests")
        
        check_burp = st.checkbox("🕸️ **Burp Suite Proxy**", value=False,
                                help="Route traffic through Burp at 127.0.0.1:8080")
        st.caption("Route traffic through Burp at 127.0.0.1:8080")
    
    st.markdown('</div>', unsafe_allow_html=True)

# Step 3: Start Scan
with st.container():
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    scan_button = st.button("▶️ Start Security Scan", disabled=st.session_state.is_scanning)
    
    if st.session_state.is_scanning:
        st.caption("⏱️ Estimated time: 1-3 minutes depending on target complexity")
    
    st.markdown('</div>', unsafe_allow_html=True)

# Handle scan initiation
if scan_button and not st.session_state.is_scanning:
    if not target_url:
        st.error("❌ Please enter a target URL")
    elif not (target_url.startswith('http://') or target_url.startswith('https://')):
        st.error("❌ URL must start with http:// or https://")
    else:
        # Build scan types list
        scan_types = []
        if check_recon:
            scan_types.append('recon')
        if check_vuln:
            scan_types.append('vulnerabilities')
        if check_browser:
            scan_types.append('browser')
        
        if not scan_types:
            st.error("❌ Please select at least one scan option")
        else:
            st.session_state.is_scanning = True
            
            # Progress bar
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            with st.spinner("🔍 Scanning in progress..."):
                try:
                    status_text.text("Initializing scan...")
                    progress_bar.progress(10)
                    
                    # Run the scan
                    scanner = st.session_state.scanner
                    results = scanner.scan(
                        target_url=target_url,
                        scan_types=scan_types,
                        use_burp=check_burp,
                        use_selenium=check_browser
                    )
                    
                    progress_bar.progress(100)
                    status_text.text("Scan completed!")
                    
                    st.session_state.scan_results = results
                    st.session_state.current_scan_id = results.get('scan_id')
                    st.session_state.is_scanning = False
                    
                    st.success(f"✅ Scan completed! Found {results.get('total_findings', 0)} findings")
                    st.rerun()
                    
                except Exception as e:
                    st.session_state.is_scanning = False
                    st.error(f"❌ Scan failed: {str(e)}")

# Display Results
if st.session_state.scan_results:
    results = st.session_state.scan_results
    
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    
    # Results header
    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown("""
        <div class="section-header">
            <div style="font-size: 24px; margin-right: 12px;">📊</div>
            <div class="section-title">Scan Results</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown('<span class="badge" style="background: #22c55e; color: white;">Completed</span>', 
                   unsafe_allow_html=True)
    
    # Target info
    st.info(f"🎯 **Target:** {results.get('target', 'Unknown')}  |  🔖 **Scan ID:** {results.get('scan_id', 'Unknown')}")
    
    # Stats grid
    stats_cols = st.columns(5)
    severity_stats = results.get('severity_stats', {})
    
    severities = [
        ('critical', 'Critical', '#ef4444'),
        ('high', 'High', '#f97316'),
        ('medium', 'Medium', '#eab308'),
        ('low', 'Low', '#22c55e'),
        ('info', 'Info', '#3b82f6')
    ]
    
    for i, (key, label, color) in enumerate(severities):
        with stats_cols[i]:
            count = severity_stats.get(key, 0)
            st.markdown(f"""
            <div class="stat-box stat-{key}">
                <div class="stat-number" style="color: {color};">{count}</div>
                <div class="stat-label">{label}</div>
            </div>
            """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Download buttons
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.subheader("📥 Download Reports")
    
    download_cols = st.columns(3)
    scan_id = st.session_state.current_scan_id
    
    with download_cols[0]:
        if st.button("📄 Download PDF"):
            try:
                report_path = ReportGenerator.generate_report(scan_id, 'pdf')
                with open(report_path, 'rb') as f:
                    st.download_button(
                        label="⬇️ Save PDF",
                        data=f.read(),
                        file_name=f"security_report_{scan_id}.pdf",
                        mime="application/pdf"
                    )
            except Exception as e:
                st.error(f"PDF generation failed: {e}")
    
    with download_cols[1]:
        if st.button("🌐 Download HTML"):
            try:
                report_path = ReportGenerator.generate_report(scan_id, 'html')
                with open(report_path, 'r', encoding='utf-8') as f:
                    st.download_button(
                        label="⬇️ Save HTML",
                        data=f.read(),
                        file_name=f"security_report_{scan_id}.html",
                        mime="text/html"
                    )
            except Exception as e:
                st.error(f"HTML generation failed: {e}")
    
    with download_cols[2]:
        if st.button("📋 Download JSON"):
            try:
                report_path = ReportGenerator.generate_report(scan_id, 'json')
                with open(report_path, 'r', encoding='utf-8') as f:
                    st.download_button(
                        label="⬇️ Save JSON",
                        data=f.read(),
                        file_name=f"security_report_{scan_id}.json",
                        mime="application/json"
                    )
            except Exception as e:
                st.error(f"JSON generation failed: {e}")
    
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Detailed Findings
    st.markdown('<div class="glass-card">', unsafe_allow_html=True)
    st.markdown("""
    <div class="section-header">
        <div style="font-size: 20px; margin-right: 12px;">📋</div>
        <div class="section-title">Detailed Findings</div>
    </div>
    """, unsafe_allow_html=True)
    
    findings = results.get('findings', [])
    
    if findings:
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            title = finding.get('title', 'Unknown')
            description = finding.get('description', 'No description available')
            finding_type = finding.get('type', 'Unknown')
            remediation = finding.get('remediation', '')
            
            with st.expander(f"{title} ({finding_type})", expanded=False):
                st.markdown(f"""
                <div class="finding-card finding-{severity}">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
                        <span class="badge badge-{severity}">{severity.upper()}</span>
                        <strong>{title}</strong>
                    </div>
                    <p>{description}</p>
                    <div style="margin-top: 10px; padding: 10px; background: rgba(255,255,255,0.5); border-radius: 8px;">
                        <strong>🛠️ Remediation:</strong> {remediation if remediation else 'Review and fix the identified issue'}
                    </div>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="empty-state">
            <h3>✨ No Vulnerabilities Found</h3>
            <p>The target appears to be secure. No security issues were detected.</p>
        </div>
        """, unsafe_allow_html=True)
    
    st.markdown('</div>', unsafe_allow_html=True)

# Scan History Section
st.markdown('<div class="glass-card">', unsafe_allow_html=True)
st.markdown("""
<div class="section-header">
    <div style="font-size: 20px; margin-right: 12px;">🕐</div>
    <div class="section-title">Recent Scans</div>
</div>
""", unsafe_allow_html=True)

# Load and display history
if st.button("🔄 Refresh History"):
    st.rerun()

try:
    history = st.session_state.scanner.get_scan_history()
    
    if history and len(history) > 0:
        for item in history[-10:]:  # Show last 10 scans
            scan_id = item.get('scan_id', 'Unknown')
            target = item.get('target', 'Unknown')
            status = item.get('status', 'unknown')
            timestamp = item.get('timestamp', 'Unknown')
            total_findings = item.get('total_findings', 0)
            
            status_color = {
                'completed': '#22c55e',
                'running': '#3b82f6',
                'error': '#ef4444'
            }.get(status, '#94a3b8')
            
            st.markdown(f"""
            <div class="history-item">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>{target}</strong>
                        <div style="font-size: 12px; color: #64748b; margin-top: 4px;">
                            {timestamp} • ID: {scan_id[:8]}...
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <span class="badge" style="background: {status_color}; color: white;">{status.upper()}</span>
                        <div style="font-size: 13px; font-weight: 700; margin-top: 4px; color: #ef4444;">
                            {total_findings} findings
                        </div>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="empty-state">
            <h3>📋 No Scans Yet</h3>
            <p>Run your first security scan to see results here</p>
        </div>
        """, unsafe_allow_html=True)
        
except Exception as e:
    st.info("📋 No scan history available yet")

st.markdown('</div>', unsafe_allow_html=True)

# Footer
st.markdown("""
<div style="text-align: center; padding: 20px; color: rgba(255,255,255,0.7); font-size: 14px;">
    <p>Built with 🔒 Python + Streamlit | Security Scanner v1.0</p>
</div>
""", unsafe_allow_html=True)
