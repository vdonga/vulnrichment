#!/usr/bin/env python3
"""
CVE Index Generator for CISA Vulnrichment Viewer

This script scans all CVE JSON files in the repository and generates
a single index file (cve-index.json) containing essential information
from each CVE for display in the web viewer.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Any
import sys

def extract_cve_data(cve_file: Path) -> Dict[str, Any]:
    """Extract essential CVE data from a JSON file."""
    try:
        with open(cve_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        cve_id = data.get('cveMetadata', {}).get('cveId', 'Unknown')
        
        # Extract CISA ADP data
        adp_container = None
        containers = data.get('containers', {})
        adp_list = containers.get('adp', [])
        
        for adp in adp_list:
            if adp.get('providerMetadata', {}).get('shortName') == 'CISA-ADP':
                adp_container = adp
                break
        
        # Extract CNA data
        cna_container = containers.get('cna', {})
        
        # Get CVSS score and severity
        cvss_score = None
        severity = None
        
        # Try CISA ADP metrics first
        if adp_container:
            metrics = adp_container.get('metrics', [])
            for metric in metrics:
                if 'cvssV3_1' in metric:
                    cvss_score = metric['cvssV3_1'].get('baseScore')
                    severity = metric['cvssV3_1'].get('baseSeverity')
                    break
        
        # Fall back to CNA metrics
        if cvss_score is None:
            metrics = cna_container.get('metrics', [])
            for metric in metrics:
                if 'cvssV3_1' in metric:
                    cvss_score = metric['cvssV3_1'].get('baseScore')
                    severity = metric['cvssV3_1'].get('baseSeverity')
                    break
        
        # Get description
        description = None
        descriptions = cna_container.get('descriptions', [])
        if descriptions:
            description = descriptions[0].get('value', '')
        
        # Get vendor and product from affected
        vendor = None
        product = None
        affected = cna_container.get('affected', [])
        if adp_container:
            affected = adp_container.get('affected', []) + affected
        
        if affected:
            vendor = affected[0].get('vendor', '')
            product = affected[0].get('product', '')
        
        # Get SSVC exploitation status
        exploitation = None
        if adp_container:
            metrics = adp_container.get('metrics', [])
            for metric in metrics:
                if 'other' in metric and metric['other'].get('type') == 'ssvc':
                    options = metric['other'].get('content', {}).get('options', [])
                    for option in options:
                        if 'Exploitation' in option:
                            exploitation = option['Exploitation']
                            break
        
        # Check if on KEV
        is_kev = False
        if adp_container:
            metrics = adp_container.get('metrics', [])
            for metric in metrics:
                if 'other' in metric and metric['other'].get('type') == 'kev':
                    is_kev = True
                    break
        
        # Get published date
        published = data.get('cveMetadata', {}).get('datePublished', '')
        
        return {
            'cveId': cve_id,
            'severity': severity,
            'score': cvss_score,
            'vendor': vendor,
            'product': product,
            'description': description,
            'exploitation': exploitation,
            'published': published,
            'isKEV': is_kev,
            'filePath': str(cve_file.relative_to(repo_root))
        }
    
    except Exception as e:
        print(f"Error processing {cve_file}: {e}", file=sys.stderr)
        return None

def generate_index(repo_root: Path, output_file: Path, max_cves: int = None):
    """Generate index file from all CVE JSON files."""
    print("Scanning for CVE JSON files...")
    
    cve_files = list(repo_root.glob('*/*/CVE-*.json'))
    total_files = len(cve_files)
    
    print(f"Found {total_files:,} CVE files")
    
    if max_cves:
        print(f"Limiting to {max_cves:,} CVEs for testing...")
        cve_files = cve_files[:max_cves]
    
    cves = []
    processed = 0
    
    for cve_file in cve_files:
        cve_data = extract_cve_data(cve_file)
        if cve_data:
            cves.append(cve_data)
        
        processed += 1
        if processed % 1000 == 0:
            print(f"Processed {processed:,} / {len(cve_files):,} files...", end='\r')
    
    print(f"\nSuccessfully processed {len(cves):,} CVEs")
    
    # Sort by CVE ID (most recent first)
    cves.sort(key=lambda x: x['cveId'], reverse=True)
    
    # Create index object
    index = {
        'generated': str(Path.ctime(output_file)) if output_file.exists() else '',
        'totalCount': len(cves),
        'cves': cves
    }
    
    # Write to file
    print(f"Writing index to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(index, f, indent=2)
    
    # Calculate file size
    file_size_mb = output_file.stat().st_size / (1024 * 1024)
    print(f"Index file created: {file_size_mb:.2f} MB")
    print(f"✅ Done! Generated index with {len(cves):,} CVEs")

if __name__ == '__main__':
    # Get repository root
    repo_root = Path(__file__).parent
    output_file = repo_root / 'docs' / 'cve-index.json'
    
    # Check if we should limit the number of CVEs (for testing)
    max_cves = None
    if len(sys.argv) > 1:
        try:
            max_cves = int(sys.argv[1])
            print(f"Limiting to {max_cves:,} CVEs (test mode)")
        except ValueError:
            print("Usage: python3 generate_index.py [max_cves]")
            sys.exit(1)
    
    generate_index(repo_root, output_file, max_cves)
