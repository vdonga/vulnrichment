#!/usr/bin/env python3
"""
Fetch NVD data and compare with CISA data for quality analysis.
This script fetches CVE data from NVD API and compares it with local CISA data.
"""

import json
import time
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys

# NVD API endpoint
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def extract_cve_id_from_path(cve_file: Path) -> str:
    """Extract CVE ID from file path."""
    return cve_file.stem  # CVE-2020-1234.json -> CVE-2020-1234

def fetch_nvd_data(cve_id: str, api_key: Optional[str] = None) -> tuple[Optional[Dict], str]:
    """Fetch CVE data from NVD API.
    
    Returns:
        tuple: (data, status) where status is 'success', 'not_found', 'rate_limited', or 'error'
    """
    # Use API key for higher rate limits (50 requests per 30 seconds vs 5)
    if api_key is None:
        api_key = "929aa498-30f9-4e8f-9434-e1b29a10346d"
    
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    headers = {}
    
    if api_key:
        headers['apiKey'] = api_key
    
    try:
        print(f"Fetching {cve_id} from NVD...", end=' ')
        response = requests.get(url, headers=headers, timeout=10)
        
        # No delay - rely on retry mechanism for rate-limited requests
        # This maximizes speed: fast initial pass, then retry rate-limited CVEs
        
        if response.status_code == 200:
            data = response.json()
            if data.get('vulnerabilities'):
                print("✓")
                return data['vulnerabilities'][0]['cve'], 'success'
            else:
                print("✗ (not found)")
                return None, 'not_found'
        elif response.status_code == 403 or response.status_code == 429:
            # Rate limited
            print(f"⏳ (rate limited)")
            return None, 'rate_limited'
        else:
            print(f"✗ (HTTP {response.status_code})")
            return None, 'error'
    except Exception as e:
        print(f"✗ (error: {e})")
        return None, 'error'

def extract_cisa_data(cve_file: Path) -> Dict[str, Any]:
    """Extract relevant data from CISA JSON file."""
    try:
        with open(cve_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        cve_id = data.get('cveMetadata', {}).get('cveId', 'Unknown')
        
        # Find CISA ADP container
        adp_container = None
        containers = data.get('containers', {})
        adp_list = containers.get('adp', [])
        
        for adp in adp_list:
            if adp.get('providerMetadata', {}).get('shortName') == 'CISA-ADP':
                adp_container = adp
                break
        
        # Get CNA container
        cna_container = containers.get('cna', {})
        
        # Extract description
        description = None
        descriptions = cna_container.get('descriptions', [])
        if descriptions:
            description = descriptions[0].get('value', '')
        
        # Extract CVSS from CISA ADP first, then fall back to CNA
        cisa_score = None
        cisa_severity = None
        
        if adp_container:
            metrics = adp_container.get('metrics', [])
            for metric in metrics:
                if 'cvssV3_1' in metric:
                    cisa_score = metric['cvssV3_1'].get('baseScore')
                    cisa_severity = metric['cvssV3_1'].get('baseSeverity')
                    break
                elif 'cvssV3_0' in metric:
                    cisa_score = metric['cvssV3_0'].get('baseScore')
                    cisa_severity = metric['cvssV3_0'].get('baseSeverity')
                    break
                elif 'cvssV4_0' in metric:
                    cisa_score = metric['cvssV4_0'].get('baseScore')
                    cisa_severity = metric['cvssV4_0'].get('baseSeverity')
                    break
        
        # Fall back to CNA if CISA ADP doesn't have CVSS
        if cisa_score is None:
            metrics = cna_container.get('metrics', [])
            for metric in metrics:
                if 'cvssV3_1' in metric:
                    cisa_score = metric['cvssV3_1'].get('baseScore')
                    cisa_severity = metric['cvssV3_1'].get('baseSeverity')
                    break
                elif 'cvssV3_0' in metric:
                    cisa_score = metric['cvssV3_0'].get('baseScore')
                    cisa_severity = metric['cvssV3_0'].get('baseSeverity')
                    break
                elif 'cvssV4_0' in metric:
                    cisa_score = metric['cvssV4_0'].get('baseScore')
                    cisa_severity = metric['cvssV4_0'].get('baseSeverity')
                    break
        
        # Extract affected products from CISA ADP first, then fall back to CNA
        cisa_affected = []
        raw_affected = []  # Store raw affected array for popup
        
        # Try CISA ADP first
        if adp_container:
            affected = adp_container.get('affected', [])
            raw_affected = affected  # Store raw data
            for aff in affected:
                vendor = aff.get('vendor', '')
                product = aff.get('product', '')
                versions = aff.get('versions', [])
                
                for ver in versions:
                    cisa_affected.append({
                        'vendor': vendor,
                        'product': product,
                        'version': ver.get('version', 'N/A'),
                        'status': ver.get('status', ''),
                        'versionType': ver.get('versionType', ''),
                        'lessThan': ver.get('lessThan', ''),
                        'lessThanOrEqual': ver.get('lessThanOrEqual', ''),
                        'versionStartIncluding': ver.get('versionStartIncluding', ''),
                        'versionEndIncluding': ver.get('versionEndIncluding', ''),
                        'versionEndExcluding': ver.get('versionEndExcluding', '')
                    })
        
        # If CISA ADP doesn't have affected products, use CNA data
        if len(cisa_affected) == 0:
            affected = cna_container.get('affected', [])
            raw_affected = affected  # Store raw data
            for aff in affected:
                vendor = aff.get('vendor', '')
                product = aff.get('product', '')
                versions = aff.get('versions', [])
                
                for ver in versions:
                    cisa_affected.append({
                        'vendor': vendor,
                        'product': product,
                        'version': ver.get('version', 'N/A'),
                        'status': ver.get('status', ''),
                        'versionType': ver.get('versionType', ''),
                        'lessThan': ver.get('lessThan', ''),
                        'lessThanOrEqual': ver.get('lessThanOrEqual', ''),
                        'versionStartIncluding': ver.get('versionStartIncluding', ''),
                        'versionEndIncluding': ver.get('versionEndIncluding', ''),
                        'versionEndExcluding': ver.get('versionEndExcluding', '')
                    })
        
        return {
            'cveId': cve_id,
            'description': description,
            'score': cisa_score,
            'severity': cisa_severity,
            'affectedProducts': cisa_affected,
            'affectedCount': len(cisa_affected),
            'rawAffected': raw_affected  # Add raw data for popup
        }
    
    except Exception as e:
        print(f"Error processing CISA file {cve_file}: {e}")
        return None

def extract_nvd_data(nvd_cve: Dict) -> Dict[str, Any]:
    """Extract relevant data from NVD API response."""
    try:
        cve_id = nvd_cve.get('id', 'Unknown')
        
        # Extract description
        description = None
        descriptions = nvd_cve.get('descriptions', [])
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # Extract CVSS score
        nvd_score = None
        nvd_severity = None
        
        metrics = nvd_cve.get('metrics', {})
        
        # Try CVSS v4.0 first
        if 'cvssMetricV40' in metrics and metrics['cvssMetricV40']:
            cvss_data = metrics['cvssMetricV40'][0]['cvssData']
            nvd_score = cvss_data.get('baseScore')
            nvd_severity = cvss_data.get('baseSeverity')
        # Try CVSS v3.1
        elif 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
            cvss_data = metrics['cvssMetricV31'][0]['cvssData']
            nvd_score = cvss_data.get('baseScore')
            nvd_severity = cvss_data.get('baseSeverity')
        # Fall back to CVSS v3.0
        elif 'cvssMetricV30' in metrics and metrics['cvssMetricV30']:
            cvss_data = metrics['cvssMetricV30'][0]['cvssData']
            nvd_score = cvss_data.get('baseScore')
            nvd_severity = cvss_data.get('baseSeverity')
        
        # Extract CPEs (affected products) and parse them
        nvd_products = []
        raw_cpes = []  # Store raw CPE strings for popup
        configurations = nvd_cve.get('configurations', [])
        
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    if cpe.get('vulnerable', False):
                        cpe_uri = cpe.get('criteria', '')
                        raw_cpes.append(cpe_uri)  # Store raw CPE
                        
                        # Parse CPE: cpe:2.3:part:vendor:product:version:update:edition:lang:sw_edition:target_sw:target_hw:other
                        cpe_parts = cpe_uri.split(':')
                        if len(cpe_parts) >= 6:
                            vendor = cpe_parts[3] if len(cpe_parts) > 3 else ''
                            product = cpe_parts[4] if len(cpe_parts) > 4 else ''
                            version = cpe_parts[5] if len(cpe_parts) > 5 else '*'
                            update = cpe_parts[6] if len(cpe_parts) > 6 else ''
                            
                            # Build version string
                            version_str = version if version != '*' else ''
                            if update and update not in ['*', '-']:
                                version_str = f"{version_str} {update}".strip() if version_str else update
                            
                            nvd_products.append({
                                'vendor': vendor,
                                'product': product,
                                'version': version_str if version_str else version,
                                'versionStartIncluding': cpe.get('versionStartIncluding', ''),
                                'versionStartExcluding': cpe.get('versionStartExcluding', ''),
                                'versionEndIncluding': cpe.get('versionEndIncluding', ''),
                                'versionEndExcluding': cpe.get('versionEndExcluding', '')
                            })
        
        return {
            'cveId': cve_id,
            'description': description,
            'score': nvd_score,
            'severity': nvd_severity,
            'affectedProducts': nvd_products,
            'affectedCount': len(nvd_products),
            'rawCPEs': raw_cpes  # Add raw CPEs for popup
        }
    
    except Exception as e:
        print(f"Error processing NVD data: {e}")
        return None

def compare_cve_data(cisa_data: Dict, nvd_data: Dict) -> Dict[str, Any]:
    """Compare CISA and NVD data for a single CVE."""
    comparison = {
        'cveId': cisa_data['cveId'],
        'cisa': cisa_data,
        'nvd': nvd_data if nvd_data else {
            'cveId': cisa_data['cveId'],
            'description': None,
            'score': None,
            'severity': None,
            'affectedProducts': [],
            'affectedCount': 0
        },
        'analysis': {}
    }
    
    nvd = comparison['nvd']
    
    # Compare scores
    comparison['analysis']['hasScore'] = {
        'cisa': cisa_data['score'] is not None,
        'nvd': nvd['score'] is not None,
        'both': cisa_data['score'] is not None and nvd['score'] is not None,
        'scoresMatch': cisa_data['score'] == nvd['score'] if (cisa_data['score'] and nvd['score']) else None
    }
    
    # Count unique vendor/product/version combinations for better coverage comparison
    cisa_coverage = set()
    for product in cisa_data['affectedProducts']:
        vendor = product.get('vendor', '')
        prod = product.get('product', '')
        version = product.get('version', '')
        cisa_coverage.add(f"{vendor}|{prod}|{version}")
    
    nvd_coverage = set()
    for product in nvd['affectedProducts']:
        vendor = product.get('vendor', '')
        prod = product.get('product', '')
        version = product.get('version', '')
        nvd_coverage.add(f"{vendor}|{prod}|{version}")
    
    cisa_coverage_count = len(cisa_coverage)
    nvd_coverage_count = len(nvd_coverage)
    
    # Determine who has better coverage
    better_coverage = 'equal'
    if cisa_coverage_count > nvd_coverage_count:
        better_coverage = 'cisa'
    elif nvd_coverage_count > cisa_coverage_count:
        better_coverage = 'nvd'
    
    # Compare affected products
    comparison['analysis']['hasAffectedProducts'] = {
        'cisa': cisa_data['affectedCount'] > 0,
        'nvd': nvd['affectedCount'] > 0,
        'both': cisa_data['affectedCount'] > 0 and nvd['affectedCount'] > 0,
        'cisaCount': cisa_data['affectedCount'],
        'nvdCount': nvd['affectedCount'],
        'cisaCoverageCount': cisa_coverage_count,
        'nvdCoverageCount': nvd_coverage_count,
        'betterCoverage': better_coverage
    }
    
    return comparison

def generate_sample_comparison(repo_root: Path, sample_size: int = 100, start_year: int = 2020, specific_year: int = None, exclude_cves: set = None):
    """Generate comparison data for a sample of CVEs from specified year onwards.
    
    Args:
        repo_root: Root directory of the repository
        sample_size: Number of CVEs to sample
        start_year: Starting year (default 2020) - used when specific_year is None
        specific_year: If set, only process CVEs from this specific year
        exclude_cves: Set of CVE IDs to exclude from processing
    
    Returns:
        tuple: (comparisons, failed_cves) where failed_cves is a dict of CVE IDs that failed due to rate limiting
    """
    if exclude_cves is None:
        exclude_cves = set()
    
    if specific_year:
        print(f"Scanning for CVE files from year {specific_year} only...")
        year_files = list(repo_root.glob(f'{specific_year}/*/CVE-*.json'))
        print(f"Found {len(year_files)} CVE files from {specific_year}")
        all_cve_files = year_files
    else:
        print(f"Scanning for CVE files from {start_year} onwards...")
        
        # Get CVEs from all years from start_year to current year
        current_year = 2025
        all_cve_files = []
        
        for year in range(start_year, current_year + 1):
            year_files = list(repo_root.glob(f'{year}/*/CVE-*.json'))
            print(f"Found {len(year_files)} CVE files from {year}")
            all_cve_files.extend(year_files)
    
    # Filter out already processed CVEs if exclude list provided
    if exclude_cves:
        original_count = len(all_cve_files)
        all_cve_files = [f for f in all_cve_files if extract_cve_id_from_path(f) not in exclude_cves]
        excluded_count = original_count - len(all_cve_files)
        print(f"Excluded {excluded_count} already-processed CVEs")
    
    print(f"Total CVE files found: {len(all_cve_files)}")
    
    # Sample CVEs
    import random
    if sample_size > 0 and sample_size < len(all_cve_files):
        sample_files = random.sample(all_cve_files, sample_size)
        print(f"\nProcessing {len(sample_files)} sample CVEs...\n")
    else:
        sample_files = all_cve_files
        print(f"\nProcessing all {len(sample_files)} CVEs...\n")
    
    comparisons = []
    rate_limited_cves = []
    failed_cves = []
    
    # Get current total for progress tracking - check batches directory first
    current_total = 0
    batches_dir = repo_root / 'batches'
    if batches_dir.exists():
        # Count CVEs from all batch files
        try:
            for batch_file in batches_dir.glob('batch_*.json'):
                with open(batch_file, 'r') as f:
                    batch_data = json.load(f)
                    current_total += len(batch_data)
        except:
            pass
    
    # If no batches, check the final merged file
    if current_total == 0:
        json_output = repo_root / 'docs' / 'comparison-data.json'
        if json_output.exists():
            try:
                with open(json_output, 'r') as f:
                    existing_data = json.load(f)
                    current_total = len(existing_data)
            except:
                pass
    
    TOTAL_TARGET = 112228
    
    for idx, cve_file in enumerate(sample_files, 1):
        # Show progress with decreasing counter from 112K
        global_processed = current_total + idx
        remaining = TOTAL_TARGET - global_processed
        print(f"[{idx}/{len(sample_files)}] Remaining: {remaining:,}/{TOTAL_TARGET:,} ", end='')
        
        # Extract CISA data
        cisa_data = extract_cisa_data(cve_file)
        if not cisa_data:
            continue
        
        # Fetch NVD data
        nvd_cve, status = fetch_nvd_data(cisa_data['cveId'])
        
        if status == 'rate_limited':
            rate_limited_cves.append(cisa_data['cveId'])
            # Still create comparison with null NVD data
            nvd_data = None
        elif status == 'success':
            nvd_data = extract_nvd_data(nvd_cve) if nvd_cve else None
        else:
            # not_found or error
            nvd_data = None
            if status == 'error':
                failed_cves.append(cisa_data['cveId'])
        
        # Compare
        comparison = compare_cve_data(cisa_data, nvd_data)
        comparisons.append(comparison)
    
    # Save rate-limited CVEs to a file for retry
    if rate_limited_cves:
        retry_file = repo_root / 'rate_limited_cves.txt'
        with open(retry_file, 'w') as f:
            for cve_id in rate_limited_cves:
                f.write(f"{cve_id}\n")
        print(f"\n⚠️  {len(rate_limited_cves)} CVEs were rate-limited and saved to: {retry_file}")
        print(f"   Run script again with --retry flag to process these CVEs")
    
    if failed_cves:
        failed_file = repo_root / 'failed_cves.txt'
        with open(failed_file, 'w') as f:
            for cve_id in failed_cves:
                f.write(f"{cve_id}\n")
        print(f"\n⚠️  {len(failed_cves)} CVEs failed and saved to: {failed_file}")
    
    return comparisons, rate_limited_cves

def generate_html_report(comparisons: List[Dict], output_file: Path):
    """Generate an HTML report showing the comparison."""
    
    # Calculate summary statistics
    total = len(comparisons)
    cisa_has_score = sum(1 for c in comparisons if c['analysis']['hasScore']['cisa'])
    nvd_has_score = sum(1 for c in comparisons if c['analysis']['hasScore']['nvd'])
    both_have_score = sum(1 for c in comparisons if c['analysis']['hasScore']['both'])
    
    cisa_has_products = sum(1 for c in comparisons if c['analysis']['hasAffectedProducts']['cisa'])
    nvd_has_products = sum(1 for c in comparisons if c['analysis']['hasAffectedProducts']['nvd'])
    both_have_products = sum(1 for c in comparisons if c['analysis']['hasAffectedProducts']['both'])
    
    # Calculate who has better coverage (wins)
    cisa_better_coverage = sum(1 for c in comparisons if c['analysis']['hasAffectedProducts']['betterCoverage'] == 'cisa')
    nvd_better_coverage = sum(1 for c in comparisons if c['analysis']['hasAffectedProducts']['betterCoverage'] == 'nvd')
    equal_coverage = sum(1 for c in comparisons if c['analysis']['hasAffectedProducts']['betterCoverage'] == 'equal')
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CISA vs NVD Quality Comparison - Sample Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f7fa;
            padding: 20px;
            line-height: 1.6;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        h1 {{
            color: #1a1a1a;
            margin-bottom: 10px;
        }}
        
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        .stat-card h3 {{
            font-size: 0.9em;
            color: #666;
            margin-bottom: 10px;
            text-transform: uppercase;
        }}
        
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #0066cc;
        }}
        
        .stat-label {{
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }}
        
        .comparison-table {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        thead {{
            background: #0066cc;
            color: white;
        }}
        
        th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e0e0e0;
        }}
        
        tbody tr:hover {{
            background: #f5f7fa;
        }}
        
        .cve-id {{
            font-weight: 600;
            color: #0066cc;
        }}
        
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }}
        
        .badge-yes {{
            background: #28a745;
            color: white;
        }}
        
        .badge-no {{
            background: #dc3545;
            color: white;
        }}
        
        .badge-cisa {{
            background: #0066cc;
            color: white;
        }}
        
        .badge-nvd {{
            background: #fd7e14;
            color: white;
        }}
        
        .badge-equal {{
            background: #6c757d;
            color: white;
        }}
        
        .details {{
            cursor: pointer;
            color: #0066cc;
            text-decoration: underline;
        }}
        
        .expanded-row {{
            background: #f9f9f9;
        }}
        
        .expanded-content {{
            padding: 20px;
            display: none;
        }}
        
        .expanded-content.active {{
            display: block;
        }}
        
        .data-section {{
            margin-bottom: 20px;
        }}
        
        .data-section h4 {{
            color: #0066cc;
            margin-bottom: 10px;
        }}
        
        .side-by-side {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }}
        
        .source-data {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            border: 2px solid #e0e0e0;
        }}
        
        .source-data h5 {{
            margin-bottom: 10px;
            color: #1a1a1a;
        }}
        
        .product-list {{
            font-size: 0.9em;
            color: #666;
            max-height: 200px;
            overflow-y: auto;
        }}
        
        .product-item {{
            padding: 5px 0;
            border-bottom: 1px solid #f0f0f0;
        }}
        
        .json-icon {{
            cursor: pointer;
            color: #0066cc;
            font-size: 1.2em;
            margin-left: 8px;
            text-decoration: none;
            display: inline-block;
        }}
        
        .json-icon:hover {{
            color: #004999;
        }}
        
        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.6);
        }}
        
        .modal-content {{
            background-color: #fefefe;
            margin: 5% auto;
            padding: 20px;
            border: 1px solid #888;
            border-radius: 8px;
            width: 80%;
            max-width: 900px;
            max-height: 80vh;
            overflow-y: auto;
        }}
        
        .close {{
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }}
        
        .close:hover,
        .close:focus {{
            color: #000;
        }}
        
        .modal h3 {{
            color: #0066cc;
            margin-top: 0;
        }}
        
        pre {{
            background: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9em;
            line-height: 1.4;
        }}
    </style>
</head>
<body>
    <div id="jsonModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h3>Raw Affected Products Data</h3>
            <pre id="jsonContent"></pre>
        </div>
    </div>
    
    <div class="container">
        <h1>🛡️ CISA vs NVD Quality Comparison</h1>
        <p class="subtitle">Sample analysis of {total} CVEs from 2025</p>
        
        <div class="summary">
            <div class="stat-card">
                <h3>Total CVEs Analyzed</h3>
                <div class="stat-value">{total}</div>
                <div class="stat-label">From 2025</div>
            </div>
            
            <div class="stat-card">
                <h3>CVSS Score Coverage</h3>
                <div class="stat-value">{cisa_has_score}/{nvd_has_score}</div>
                <div class="stat-label">CISA / NVD ({both_have_score} both)</div>
            </div>
            
            <div class="stat-card">
                <h3>Affected Products Coverage</h3>
                <div class="stat-value">{cisa_has_products}/{nvd_has_products}</div>
                <div class="stat-label">CISA / NVD ({both_have_products} both)</div>
            </div>
            
            <div class="stat-card">
                <h3>Better CPE Coverage Quality</h3>
                <div class="stat-value">{cisa_better_coverage}/{nvd_better_coverage}</div>
                <div class="stat-label">CISA wins / NVD wins ({equal_coverage} equal)</div>
            </div>
            
            <div class="stat-card">
                <h3>Completeness</h3>
                <div class="stat-value">{int(cisa_has_score/total*100)}%/{int(nvd_has_score/total*100)}%</div>
                <div class="stat-label">CISA / NVD (scores)</div>
            </div>
        </div>
        
        <div class="comparison-table">
            <table>
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>CISA Score</th>
                        <th>NVD Score</th>
                        <th>Match?</th>
                        <th>CISA Products</th>
                        <th>NVD CPEs</th>
                        <th>Better CPE Coverage</th>
                        <th>Details</th>
                    </tr>
                </thead>
                <tbody>
"""
    
    for idx, comp in enumerate(comparisons):
        cisa = comp['cisa']
        nvd = comp['nvd']
        analysis = comp['analysis']
        
        cisa_score_badge = f'<span class="badge badge-yes">{cisa["score"]}</span>' if cisa['score'] else '<span class="badge badge-no">None</span>'
        nvd_score_badge = f'<span class="badge badge-yes">{nvd["score"]}</span>' if nvd['score'] else '<span class="badge badge-no">None</span>'
        
        match_badge = ''
        if analysis['hasScore']['both']:
            if analysis['hasScore']['scoresMatch']:
                match_badge = '<span class="badge badge-yes">✓</span>'
            else:
                match_badge = '<span class="badge badge-no">✗</span>'
        else:
            match_badge = '<span class="badge badge-equal">N/A</span>'
        
        better_coverage = analysis['hasAffectedProducts']['betterCoverage']
        coverage_badge = ''
        if better_coverage == 'cisa':
            coverage_badge = '<span class="badge badge-cisa">CISA</span>'
        elif better_coverage == 'nvd':
            coverage_badge = '<span class="badge badge-nvd">NVD</span>'
        else:
            coverage_badge = '<span class="badge badge-equal">Equal</span>'
        
        html += f"""
                    <tr onclick="toggleDetails({idx})">
                        <td class="cve-id">{comp['cveId']}</td>
                        <td>{cisa_score_badge}</td>
                        <td>{nvd_score_badge}</td>
                        <td>{match_badge}</td>
                        <td>{cisa['affectedCount']}</td>
                        <td>{nvd['affectedCount']}</td>
                        <td>{coverage_badge}</td>
                        <td><span class="details">View</span></td>
                    </tr>
                    <tr class="expanded-row">
                        <td colspan="8">
                            <div class="expanded-content" id="details-{idx}">
                                <div class="data-section">
                                    <h4>Descriptions</h4>
                                    <div class="side-by-side">
                                        <div class="source-data">
                                            <h5>CISA Description</h5>
                                            <p>{cisa.get('description', 'N/A')[:500]}</p>
                                        </div>
                                        <div class="source-data">
                                            <h5>NVD Description</h5>
                                            <p>{nvd.get('description', 'N/A')[:500] if nvd.get('description') else 'N/A'}</p>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="data-section">
                                    <h4>Affected Products</h4>
                                    <div class="side-by-side">
                                        <div class="source-data">
                                            <h5>CISA Affected Products ({cisa['affectedCount']})
                                                <a class="json-icon" onclick="showJson('cisa-{idx}')" title="View raw JSON">📋</a>
                                            </h5>
                                            <div class="product-list">
"""
        
        for product in cisa['affectedProducts'][:10]:
            vendor_product = f"{product['vendor']} / {product['product']}"
            
            # Build version string with all available info
            version_parts = []
            
            # Handle version field - check if it contains range operators
            version_val = product.get('version', '')
            if version_val and version_val not in ['*', 'n/a', 'N/A']:
                # If version already contains operators, use as-is
                if any(op in version_val for op in ['<', '>', '≤', '≥', '=']):
                    version_parts.append(version_val)
                else:
                    # Otherwise add 'v' prefix for normal versions
                    version_parts.append(f"v{version_val}")
            
            # Add range constraints from separate fields
            if product.get('lessThan'):
                version_parts.append(f"< {product['lessThan']}")
            if product.get('lessThanOrEqual'):
                version_parts.append(f"≤ {product['lessThanOrEqual']}")
            if product.get('versionStartIncluding'):
                version_parts.append(f"≥ {product['versionStartIncluding']}")
            if product.get('versionEndIncluding'):
                version_parts.append(f"≤ {product['versionEndIncluding']}")
            if product.get('versionEndExcluding'):
                version_parts.append(f"< {product['versionEndExcluding']}")
            
            version_info = ' '.join(version_parts) if version_parts else 'All versions'
            
            html += f'<div class="product-item"><strong>{vendor_product}</strong><br>{version_info}</div>'
        
        if cisa['affectedCount'] > 10:
            html += f'<div class="product-item"><em>... and {cisa["affectedCount"] - 10} more</em></div>'
        
        if cisa['affectedCount'] == 0:
            html += '<div class="product-item"><em>No affected products data</em></div>'
        
        html += """
                                            </div>
                                        </div>
                                        <div class="source-data">
                                            <h5>NVD CPEs (""" + str(nvd['affectedCount']) + """)</h5>
                                            <div class="product-list">
"""
        
        for cpe in nvd['affectedProducts'][:10]:
            vendor = cpe.get('vendor', 'unknown')
            product = cpe.get('product', 'unknown')
            version = cpe.get('version', '*')
            
            # Build version display
            version_parts = []
            if version and version != '*':
                version_parts.append(f"v{version}")
            if cpe.get('versionStartIncluding'):
                version_parts.append(f"≥ {cpe['versionStartIncluding']}")
            if cpe.get('versionStartExcluding'):
                version_parts.append(f"> {cpe['versionStartExcluding']}")
            if cpe.get('versionEndIncluding'):
                version_parts.append(f"≤ {cpe['versionEndIncluding']}")
            if cpe.get('versionEndExcluding'):
                version_parts.append(f"< {cpe['versionEndExcluding']}")
            
            version_str = ' '.join(version_parts) if version_parts else 'All versions'
            html += f'<div class="product-item"><strong>{vendor} / {product}</strong><br>{version_str}</div>'
        
        if nvd['affectedCount'] > 10:
            html += f'<div class="product-item"><em>... and {nvd["affectedCount"] - 10} more</em></div>'
        
        if nvd['affectedCount'] == 0:
            html += '<div class="product-item"><em>No CPE data</em></div>'
        
        html += """
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </td>
                    </tr>
"""
    
    html += """
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // Store raw JSON data
        const rawAffectedData = {
"""
    
    # Add raw JSON data for each CVE
    for idx, comp in enumerate(comparisons):
        cisa_affected_json = json.dumps(comp['cisa'].get('rawAffected', []), indent=2)
        # Escape for JavaScript
        cisa_affected_json = cisa_affected_json.replace('\\', '\\\\').replace('`', '\\`').replace('${', '\\${')
        html += f"""            'cisa-{idx}': `{cisa_affected_json}`,
"""
    
    html += """        };
        
        function toggleDetails(idx) {
            const details = document.getElementById(`details-${idx}`);
            details.classList.toggle('active');
        }
        
        function showJson(key) {
            event.stopPropagation();
            const modal = document.getElementById('jsonModal');
            const content = document.getElementById('jsonContent');
            content.textContent = rawAffectedData[key];
            modal.style.display = 'block';
        }
        
        function closeModal() {
            document.getElementById('jsonModal').style.display = 'none';
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('jsonModal');
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }
    </script>
</body>
</html>
"""
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html)
    
    print(f"\nHTML report generated: {output_file}")

def save_comparison_json(comparisons: List[Dict], output_file: Path):
    """Save comparison data as JSON for web app consumption."""
    # Extract just the data needed for the web app
    json_data = []
    
    for comp in comparisons:
        cisa = comp['cisa']
        nvd = comp['nvd']
        analysis = comp['analysis']
        
        # Extract year from CVE ID (e.g., CVE-2024-12345 -> 2024)
        cve_id = comp['cveId']
        year = int(cve_id.split('-')[1]) if '-' in cve_id else None
        
        # Extract vendors and products for search
        vendors = list(set(p.get('vendor', '') for p in cisa['affectedProducts'] if p.get('vendor')))
        products = list(set(p.get('product', '') for p in cisa['affectedProducts'] if p.get('product')))
        
        json_data.append({
            'cveId': cve_id,
            'year': year,
            'cisa': {
                'description': cisa.get('description'),
                'score': cisa.get('score'),
                'severity': cisa.get('severity'),
                'affectedProducts': cisa.get('affectedProducts', []),
                'affectedCount': cisa.get('affectedCount', 0),
                'rawAffected': cisa.get('rawAffected', [])
            },
            'nvd': {
                'description': nvd.get('description'),
                'score': nvd.get('score'),
                'severity': nvd.get('severity'),
                'affectedProducts': nvd.get('affectedProducts', []),
                'affectedCount': nvd.get('affectedCount', 0),
                'rawCPEs': nvd.get('rawCPEs', [])
            },
            'analysis': {
                'scoreMatch': analysis['hasScore'].get('scoresMatch'),
                'betterCoverage': analysis['hasAffectedProducts'].get('betterCoverage'),
                'cisaCoverageCount': analysis['hasAffectedProducts'].get('cisaCoverageCount', 0),
                'nvdCoverageCount': analysis['hasAffectedProducts'].get('nvdCoverageCount', 0)
            },
            'vendors': vendors,
            'products': products
        })
    
    # Ensure parent directory exists
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(json_data, f, indent=2)
    
    print(f"\nJSON data saved: {output_file}")
    print(f"✅ Total CVEs: {len(json_data)}")

def process_retry_file(repo_root: Path, retry_file: Path):
    """Process CVEs from a retry file (rate-limited or failed CVEs).
    
    Args:
        repo_root: Root directory of the repository
        retry_file: Path to file containing CVE IDs to retry (one per line)
    
    Returns:
        tuple: (comparisons, still_failed_cves)
    """
    if not retry_file.exists():
        print(f"❌ Retry file not found: {retry_file}")
        return [], []
    
    print(f"Reading CVE IDs from: {retry_file}")
    with open(retry_file, 'r') as f:
        cve_ids = [line.strip() for line in f if line.strip()]
    
    print(f"Found {len(cve_ids)} CVEs to retry\n")
    
    comparisons = []
    still_rate_limited = []
    still_failed = []
    
    # Get current total for progress tracking - check batches directory first
    current_total = 0
    batches_dir = repo_root / 'batches'
    if batches_dir.exists():
        # Count CVEs from all batch files
        try:
            for batch_file in batches_dir.glob('batch_*.json'):
                with open(batch_file, 'r') as f:
                    batch_data = json.load(f)
                    current_total += len(batch_data)
        except:
            pass
    
    # If no batches, check the final merged file
    if current_total == 0:
        json_output = repo_root / 'docs' / 'comparison-data.json'
        if json_output.exists():
            try:
                with open(json_output, 'r') as f:
                    existing_data = json.load(f)
                    current_total = len(existing_data)
            except:
                pass
    
    TOTAL_TARGET = 112228
    
    for idx, cve_id in enumerate(cve_ids, 1):
        global_processed = current_total + idx
        remaining = TOTAL_TARGET - global_processed
        print(f"[{idx}/{len(cve_ids)}] Remaining: {remaining:,}/{TOTAL_TARGET:,} ", end='')
        
        # Find the CISA file for this CVE
        year = cve_id.split('-')[1]
        cve_files = list(repo_root.glob(f'{year}/*/{cve_id}.json'))
        
        if not cve_files:
            print(f"⚠️  CISA file not found for {cve_id}")
            still_failed.append(cve_id)
            continue
        
        # Extract CISA data
        cisa_data = extract_cisa_data(cve_files[0])
        if not cisa_data:
            still_failed.append(cve_id)
            continue
        
        # Fetch NVD data
        nvd_cve, status = fetch_nvd_data(cve_id)
        
        if status == 'rate_limited':
            still_rate_limited.append(cve_id)
            nvd_data = None
        elif status == 'success':
            nvd_data = extract_nvd_data(nvd_cve) if nvd_cve else None
        else:
            nvd_data = None
            if status == 'error':
                still_failed.append(cve_id)
        
        # Compare
        comparison = compare_cve_data(cisa_data, nvd_data)
        comparisons.append(comparison)
    
    # Update the retry file with still rate-limited CVEs
    if still_rate_limited:
        with open(retry_file, 'w') as f:
            for cve_id in still_rate_limited:
                f.write(f"{cve_id}\n")
        print(f"\n⚠️  {len(still_rate_limited)} CVEs still rate-limited, saved to: {retry_file}")
    else:
        # All processed successfully, remove the retry file
        retry_file.unlink()
        print(f"\n✅ All CVEs from retry file processed successfully!")
    
    return comparisons, still_rate_limited

if __name__ == '__main__':
    repo_root = Path(__file__).parent
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='CISA vs NVD Quality Comparison Tool')
    parser.add_argument('sample_size', type=int, nargs='?', default=100,
                        help='Number of CVEs to sample (0 for all)')
    parser.add_argument('--start-year', type=int, default=2020,
                        help='Starting year for CVE collection (default: 2020)')
    parser.add_argument('--year', type=int, default=None,
                        help='Process only CVEs from this specific year')
    parser.add_argument('--exclude-file', type=str, default=None,
                        help='File containing CVE IDs to exclude (one per line)')
    parser.add_argument('--output', type=str, default=None,
                        help='Output file path (default: docs/comparison-data.json)')
    parser.add_argument('--retry', action='store_true',
                        help='Retry rate-limited CVEs from rate_limited_cves.txt')
    parser.add_argument('--merge', action='store_true',
                        help='Merge retry results with existing comparison-data.json')
    
    args = parser.parse_args()
    
    print(f"CISA vs NVD Quality Comparison Tool")
    print(f"=" * 50)
    
    if args.retry:
        # Process retry file
        retry_file = repo_root / 'rate_limited_cves.txt'
        comparisons, still_failed = process_retry_file(repo_root, retry_file)
        
        if args.merge and comparisons:
            # Merge with existing data
            json_output = repo_root / 'docs' / 'comparison-data.json'
            if json_output.exists():
                with open(json_output, 'r') as f:
                    existing_data = json.load(f)
                
                # Create a map of existing CVEs
                existing_cves = {item['cveId']: item for item in existing_data}
                
                # Update with new data
                for comp in comparisons:
                    cve_id = comp['cveId']
                    # Convert comparison to JSON format
                    cisa = comp['cisa']
                    nvd = comp['nvd']
                    analysis = comp['analysis']
                    year = int(cve_id.split('-')[1]) if '-' in cve_id else None
                    vendors = list(set(p.get('vendor', '') for p in cisa['affectedProducts'] if p.get('vendor')))
                    products = list(set(p.get('product', '') for p in cisa['affectedProducts'] if p.get('product')))
                    
                    existing_cves[cve_id] = {
                        'cveId': cve_id,
                        'year': year,
                        'cisa': {
                            'description': cisa.get('description'),
                            'score': cisa.get('score'),
                            'severity': cisa.get('severity'),
                            'affectedProducts': cisa.get('affectedProducts', []),
                            'affectedCount': cisa.get('affectedCount', 0),
                            'rawAffected': cisa.get('rawAffected', [])
                        },
                        'nvd': {
                            'description': nvd.get('description'),
                            'score': nvd.get('score'),
                            'severity': nvd.get('severity'),
                            'affectedProducts': nvd.get('affectedProducts', []),
                            'affectedCount': nvd.get('affectedCount', 0),
                            'rawCPEs': nvd.get('rawCPEs', [])
                        },
                        'analysis': {
                            'scoreMatch': analysis['hasScore'].get('scoresMatch'),
                            'betterCoverage': analysis['hasAffectedProducts'].get('betterCoverage'),
                            'cisaCoverageCount': analysis['hasAffectedProducts'].get('cisaCoverageCount', 0),
                            'nvdCoverageCount': analysis['hasAffectedProducts'].get('nvdCoverageCount', 0)
                        },
                        'vendors': vendors,
                        'products': products
                    }
                
                # Save merged data
                merged_data = list(existing_cves.values())
                with open(json_output, 'w', encoding='utf-8') as f:
                    json.dump(merged_data, f, indent=2)
                
                print(f"\n✅ Merged {len(comparisons)} retry results with existing data")
                print(f"✅ Total CVEs in dataset: {len(merged_data)}")
                print(f"✅ Updated: {json_output}")
            else:
                # No existing data, just save retry results
                save_comparison_json(comparisons, json_output)
        else:
            # Just save retry results
            json_output = repo_root / 'docs' / 'comparison-data-retry.json'
            save_comparison_json(comparisons, json_output)
    else:
        # Normal processing
        # Load excluded CVEs if specified
        exclude_cves = set()
        if args.exclude_file:
            exclude_file = repo_root / args.exclude_file
            if exclude_file.exists():
                with open(exclude_file, 'r') as f:
                    exclude_cves = set(line.strip() for line in f if line.strip())
                print(f"Loaded {len(exclude_cves)} CVE IDs to exclude from {args.exclude_file}")
        
        comparisons, rate_limited = generate_sample_comparison(
            repo_root, 
            args.sample_size,
            args.start_year,
            args.year,
            exclude_cves
        )
        
        # Determine output file path
        if args.output:
            json_output = Path(args.output)
        else:
            json_output = repo_root / 'docs' / 'comparison-data.json'
        
        # Save JSON data for web app (skip HTML to avoid errors with incomplete data)
        
        # Merge with existing data if --merge flag is set
        if args.merge and json_output.exists():
            with open(json_output, 'r') as f:
                existing_data = json.load(f)
            
            # Create a map of existing CVEs by ID
            existing_cves = {item['cveId']: item for item in existing_data}
            
            # Convert new comparisons to JSON format and add/update
            for comp in comparisons:
                cve_id = comp['cveId']
                cisa = comp['cisa']
                nvd = comp['nvd']
                analysis = comp['analysis']
                year = int(cve_id.split('-')[1]) if '-' in cve_id else None
                vendors = list(set(p.get('vendor', '') for p in cisa['affectedProducts'] if p.get('vendor')))
                products = list(set(p.get('product', '') for p in cisa['affectedProducts'] if p.get('product')))
                
                existing_cves[cve_id] = {
                    'cveId': cve_id,
                    'year': year,
                    'cisa': {
                        'description': cisa.get('description'),
                        'score': cisa.get('score'),
                        'severity': cisa.get('severity'),
                        'affectedProducts': cisa.get('affectedProducts', []),
                        'affectedCount': cisa.get('affectedCount', 0),
                        'rawAffected': cisa.get('rawAffected', [])
                    },
                    'nvd': {
                        'description': nvd.get('description'),
                        'score': nvd.get('score'),
                        'severity': nvd.get('severity'),
                        'affectedProducts': nvd.get('affectedProducts', []),
                        'affectedCount': nvd.get('affectedCount', 0),
                        'rawCPEs': nvd.get('rawCPEs', [])
                    },
                    'analysis': {
                        'scoreMatch': analysis['hasScore'].get('scoresMatch'),
                        'betterCoverage': analysis['hasAffectedProducts'].get('betterCoverage'),
                        'cisaCoverageCount': analysis['hasAffectedProducts'].get('cisaCoverageCount', 0),
                        'nvdCoverageCount': analysis['hasAffectedProducts'].get('nvdCoverageCount', 0)
                    },
                    'vendors': vendors,
                    'products': products
                }
            
            # Save merged data
            merged_data = list(existing_cves.values())
            with open(json_output, 'w', encoding='utf-8') as f:
                json.dump(merged_data, f, indent=2)
            
            print(f"\n✅ Merged {len(comparisons)} new CVEs with {len(existing_data)} existing")
            print(f"✅ Total CVEs in dataset: {len(merged_data)}")
        else:
            # No merge, just save new data
            save_comparison_json(comparisons, json_output)
        
        print(f"\n✅ JSON for web app: {json_output}")
        
        if rate_limited:
            print(f"\n💡 To retry rate-limited CVEs, run:")
            print(f"   python3 fetch_nvd_comparison.py --retry --merge")

