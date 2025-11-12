#!/usr/bin/env python3
"""
Overnight CVE indexer - processes all CVEs from 2020 onwards in batches.
Handles rate limiting automatically and can be resumed if interrupted.
"""

import json
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime

class Logger:
    """Logger that writes to both console and file."""
    def __init__(self, log_file):
        self.log_file = log_file
        self.terminal = sys.stdout
        
    def write(self, message):
        self.terminal.write(message)
        self.terminal.flush()
        with open(self.log_file, 'a') as f:
            f.write(message)
    
    def flush(self):
        self.terminal.flush()

def run_command(cmd, cwd):
    """Run a command and return exit code."""
    print(f"\nRunning: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, cwd=cwd, capture_output=False, text=True)
        return result.returncode
    except Exception as e:
        print(f"Error running command: {e}")
        return 1

def get_current_count(json_file):
    """Get current number of CVEs in the dataset."""
    if not json_file.exists():
        return 0
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
            return len(data)
    except:
        return 0

def get_rate_limited_count(rate_file):
    """Get number of rate-limited CVEs."""
    if not rate_file.exists():
        return 0
    
    try:
        with open(rate_file, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
            return len(lines)
    except:
        return 0

def update_processed_file(json_file, processed_file):
    """Update the processed CVEs file from the comparison data JSON."""
    if not json_file.exists():
        return
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
            cve_ids = [item['cveId'] for item in data if 'cveId' in item]
        
        with open(processed_file, 'w') as f:
            for cve_id in cve_ids:
                f.write(f"{cve_id}\n")
    except Exception as e:
        print(f"Warning: Could not update processed file: {e}")

def count_cves_in_batches(batches_dir):
    """Count total CVEs across all batch files."""
    total = 0
    for batch_file in batches_dir.glob('batch_*.json'):
        try:
            with open(batch_file, 'r') as f:
                data = json.load(f)
                total += len(data)
        except:
            pass
    return total

def update_processed_from_batches(batches_dir, processed_file):
    """Update processed_cves.txt from all batch files."""
    all_cve_ids = set()
    for batch_file in sorted(batches_dir.glob('batch_*.json')):
        try:
            with open(batch_file, 'r') as f:
                data = json.load(f)
                for item in data:
                    if 'cveId' in item:
                        all_cve_ids.add(item['cveId'])
        except Exception as e:
            print(f"Warning: Could not read {batch_file}: {e}")
    
    with open(processed_file, 'w') as f:
        for cve_id in sorted(all_cve_ids):
            f.write(f"{cve_id}\n")
    
    return len(all_cve_ids)

def process_year(year, batch_size, repo_root, batches_dir, rate_file, processed_file, total_target):
    """Process all CVEs from a specific year."""
    # Get count of CVE files for this year
    year_files = list(repo_root.glob(f'{year}/*/CVE-*.json'))
    total_cves_in_year = len(year_files)
    
    print(f"\n┌{'─'*78}┐")
    print(f"│ 📅 Year: {year:<20} Total CVE files: {total_cves_in_year:>6,} {' '*24}│")
    print(f"│ ⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<64}│")
    print(f"└{'─'*78}┘")
    
    max_retries = 10
    initial_total = count_cves_in_batches(batches_dir)
    
    # Calculate number of batches needed for this year
    num_batches = (total_cves_in_year + batch_size - 1) // batch_size  # Ceiling division
    
    # Check for existing batches from this year to resume from correct batch number
    existing_batches = sorted(batches_dir.glob(f'batch_{year}_*.json'))
    batch_count = len(existing_batches)
    
    # Skip year entirely if all batches already exist
    if batch_count >= num_batches:
        print(f"\n  ⏭️  All {num_batches} batches for year {year} already exist. Skipping year.")
        print(f"\n┌{'─'*78}┐")
        print(f"│ ✓ Year {year} Complete{' '*57}│")
        print(f"│ 📊 CVEs processed this year: {total_cves_in_year:>6,} (all batches exist){' '*22}│")
        print(f"│ ⏰ Skipped: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<64}│")
        print(f"└{'─'*78}┘")
        return
    
    # Process all batches for this year
    for batch_num in range(num_batches):
        batch_count += 1
        
        # Check if this batch already exists
        batch_file = batches_dir / f'batch_{year}_{batch_count:03d}.json'
        if batch_file.exists():
            print(f"\n  ⏭️  Batch #{batch_count}/{num_batches} already exists: {batch_file.name}")
            continue
        
        # Count total CVEs processed so far from all batch files
        current_total = count_cves_in_batches(batches_dir)
        remaining = total_target - current_total
        progress_pct = (current_total / total_target * 100) if total_target > 0 else 0
        
        print(f"\n  ╔═══ Batch #{batch_count}/{num_batches} ═══════════════════════════════════════════════")
        print(f"  ║ 📊 Processed: {current_total:,} | ⏳ REMAINING: {remaining:,}/{total_target:,} ({100-progress_pct:.2f}% left)")
        print(f"  ║ 📦 Processing batch of {batch_size} CVEs from year {year}...")
        print(f"  ╚═══════════════════════════════════════════════════════════════════════════")
        
        # Create batch-specific output file (already set above)
        
        # Process new batch from this year only, excluding already processed CVEs
        cmd = ['python3', 'fetch_nvd_comparison.py', str(batch_size), '--year', str(year), 
               '--output', str(batch_file)]
        if processed_file.exists():
            cmd.extend(['--exclude-file', str(processed_file.name)])
        
        exit_code = run_command(cmd, repo_root)
        
        if exit_code != 0:
            print(f"  ⚠️  Batch failed with exit code {exit_code}")
            continue
        
        # Update processed file from all batches
        processed_count = update_processed_from_batches(batches_dir, processed_file)
        
        # Show batch completion summary
        new_total = count_cves_in_batches(batches_dir)
        batch_added = new_total - current_total
        remaining_overall = total_target - new_total
        progress_pct = (new_total / total_target * 100) if total_target > 0 else 0
        
        print(f"\n  ✅ Batch #{batch_count} Complete:")
        print(f"     • Saved to: {batch_file.name}")
        print(f"     • Added {batch_added} CVEs this batch")
        print(f"     • ⏳ REMAINING: {remaining_overall:,}/{total_target:,} ({100-progress_pct:.2f}% left)")
        print(f"     • Processed so far: {new_total:,} ({progress_pct:.2f}%)")
        
        # Brief pause between batches
        if batch_num < num_batches - 1:  # Don't wait after last batch
            print(f"  ⏸️  Waiting 10 seconds before next batch...")
            time.sleep(10)
    
    final_total = count_cves_in_batches(batches_dir)
    processed_this_year = final_total - initial_total
    
    print(f"\n┌{'─'*78}┐")
    print(f"│ ✓ Year {year} Complete {' '*59}│")
    print(f"│ 📊 CVEs processed this year: {processed_this_year:>6,} {' '*40}│")
    print(f"│ 📈 Total CVEs in batches: {final_total:>9,} {' '*40}│")
    print(f"│ ⏰ Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<64}│")
    print(f"└{'─'*78}┘")
    
    return final_total
    """Process all CVEs from a specific year."""
    # Get count of CVE files for this year
    year_files = list(repo_root.glob(f'{year}/*/CVE-*.json'))
    total_cves_in_year = len(year_files)
    
    print(f"\n┌{'─'*78}┐")
    print(f"│ 📅 Year: {year:<20} Total CVE files: {total_cves_in_year:>6,} {' '*24}│")
    print(f"│ ⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<64}│")
    print(f"└{'─'*78}┘")
    
    batch_count = 0
    retry_count = 0
    max_retries = 10
    
    # Calculate number of batches needed for this year
    num_batches = (total_cves_in_year + batch_size - 1) // batch_size  # Ceiling division
    
    # Process all batches for this year
    for batch_num in range(num_batches):
        batch_count += 1
        
        # Count total CVEs processed so far from all batch files
        current_total = sum(1 for _ in batches_dir.glob('batch_*.json') if _.exists())
        remaining = total_target - current_total
        progress_pct = (current_total / total_target * 100) if total_target > 0 else 0
        
        print(f"\n  ╔═══ Batch #{batch_count}/{num_batches} ═══════════════════════════════════════════════")
        print(f"  ║ 📊 Processed: {current_total:,} | ⏳ REMAINING: {remaining:,}/{total_target:,} ({100-progress_pct:.2f}% left)")
        print(f"  ║ 📦 Processing batch of {batch_size} CVEs from year {year}...")
        print(f"  ╚═══════════════════════════════════════════════════════════════════════════")
        
        # Create batch-specific output file
        batch_file = batches_dir / f'batch_{year}_{batch_count:03d}.json'
        
        # Process new batch from this year only, excluding already processed CVEs
        cmd = ['python3', 'fetch_nvd_comparison.py', str(batch_size), '--year', str(year), 
               '--output', str(batch_file)]
        if processed_file.exists():
            cmd.extend(['--exclude-file', str(processed_file.name)])
        
        exit_code = run_command(cmd, repo_root)
        
        if exit_code != 0:
            print(f"  ⚠️  Batch failed with exit code {exit_code}")
            continue
        
        # Now handle rate-limited retries for this batch
        retry_count = 0
        while True:
            rate_limited = get_rate_limited_count(rate_file)
            
            if rate_limited == 0:
                print(f"  ✅ Batch #{batch_count} complete - no rate-limited CVEs")
                break
            
            if retry_count >= max_retries:
                print(f"\n  ⚠️  Still {rate_limited} rate-limited after {max_retries} retries")
                print(f"  📝 Saving to rate_limited_cves_{year}_batch{batch_count}.txt")
                rate_file.rename(repo_root / f'rate_limited_cves_{year}_batch{batch_count}.txt')
                break
            
            retry_count += 1
            print(f"\n  ╔═══ Retry #{retry_count}/{max_retries} for Batch #{batch_count} ═══════════════════")
            print(f"  ║ � Retrying {rate_limited} rate-limited CVEs...")
            print(f"  ╚═══════════════════════════════════════════════════════════════════════════")
            
            exit_code = run_command(
                ['python3', 'fetch_nvd_comparison.py', '--retry', '--merge'],
                repo_root
            )
            
            if exit_code != 0:
                print(f"  ⚠️  Retry command failed with exit code {exit_code}")
            
            new_rate_limited = get_rate_limited_count(rate_file)
            processed_this_retry = rate_limited - new_rate_limited
            
            print(f"\n  ✓ Processed {processed_this_retry} CVEs in this retry")
            print(f"  ⏳ {new_rate_limited} still rate-limited")
            
            if new_rate_limited == 0:
                print(f"  ✅ All rate-limited CVEs for batch #{batch_count} processed!")
                break
            
            if new_rate_limited < rate_limited:
                # Made progress, continue
                print(f"  ⏸️  Waiting 30 seconds before next retry...")
                time.sleep(30)
            else:
                # No progress
                break
        
        # Update processed CVEs file after each batch
        update_processed_file(json_file, processed_file)
        
        # Show batch completion summary
        new_total = get_current_count(json_file)
        batch_added = new_total - current_total
        remaining_overall = total_target - new_total
        progress_pct = (new_total / total_target * 100) if total_target > 0 else 0
        
        print(f"\n  ✅ Batch #{batch_count} Complete:")
        print(f"     • Added {batch_added} CVEs this batch")
        print(f"     • ⏳ REMAINING: {remaining_overall:,}/{total_target:,} ({100-progress_pct:.2f}% left)")
        print(f"     • Processed so far: {new_total:,} ({progress_pct:.2f}%)")
        
        # Brief pause between batches
        if batch_num < num_batches - 1:  # Don't wait after last batch
            print(f"  ⏸️  Waiting 10 seconds before next batch...")
            time.sleep(10)
    
    final_total = get_current_count(json_file)
    processed_this_year = final_total - initial_total
    
    print(f"\n┌{'─'*78}┐")
    print(f"│ ✓ Year {year} Complete {' '*59}│")
    print(f"│ 📊 CVEs processed this year: {processed_this_year:>6,} {' '*40}│")
    print(f"│ 📈 Total CVEs in dataset: {final_total:>9,} {' '*40}│")
    print(f"│ ⏰ Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S'):<64}│")
    print(f"└{'─'*78}┘")
    
    return final_total

def main():
    """Main overnight indexer."""
    repo_root = Path(__file__).parent
    json_file = repo_root / 'docs' / 'comparison-data.json'
    batches_dir = repo_root / 'batches'
    rate_file = repo_root / 'rate_limited_cves.txt'
    log_file = repo_root / 'overnight_indexer.log'
    
    # Create batches directory
    batches_dir.mkdir(exist_ok=True)
    
    # Setup logger
    sys.stdout = Logger(log_file)
    sys.stderr = sys.stdout
    
    # Configuration
    years = [2020, 2021, 2022, 2023, 2024, 2025]
    batch_size = 1000  # Process 1000 CVEs per batch
    
    # Calculate total CVEs to process
    total_cve_files = 0
    for year in years:
        year_files = list(repo_root.glob(f'{year}/*/CVE-*.json'))
        total_cve_files += len(year_files)
    
    # Processed CVEs tracking file
    processed_file = repo_root / 'processed_cves.txt'
    
    print(f"\n{'='*80}")
    print(f"🚀 OVERNIGHT CVE INDEXER STARTED")
    print(f"{'='*80}")
    print(f"⏰ Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"📅 Years to process: {', '.join(map(str, years))}")
    print(f"📦 Batch size: {batch_size}")
    print(f"📊 Total CVE files available: {total_cve_files:,}")
    print(f"💾 Batches directory: {batches_dir}")
    print(f"💾 Final output file: {json_file}")
    print(f"📝 Log file: {log_file}")
    print(f"{'='*80}\n")
    
    try:
        for idx, year in enumerate(years, 1):
            print(f"\n{'█'*80}")
            print(f"█ YEAR {year} ({idx}/{len(years)}) - {(idx-1)/len(years)*100:.1f}% of years complete")
            print(f"{'█'*80}")
            process_year(year, batch_size, repo_root, batches_dir, rate_file, processed_file, total_cve_files)
            
            if idx < len(years):
                print(f"\n⏳ Waiting 60 seconds before processing year {years[idx]}...")
                time.sleep(60)
        
        print(f"\n{'='*80}")
        print(f"✅ ALL YEARS PROCESSED SUCCESSFULLY!")
        print(f"{'='*80}")
        
        # Merge all batches into final file
        print(f"\n🔄 Merging all batch files into final comparison-data.json...")
        all_cves = {}
        batch_files = sorted(batches_dir.glob('batch_*.json'))
        
        for batch_file in batch_files:
            try:
                with open(batch_file, 'r') as f:
                    data = json.load(f)
                    for item in data:
                        # Use CVE ID as key to avoid duplicates
                        all_cves[item['cveId']] = item
                print(f"  ✓ Merged {batch_file.name}")
            except Exception as e:
                print(f"  ⚠️  Error reading {batch_file.name}: {e}")
        
        # Save final merged file
        final_data = list(all_cves.values())
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(final_data, f, indent=2)
        
        print(f"\n✅ Final merge complete!")
        print(f"📊 Total batches merged: {len(batch_files)}")
        print(f"📊 Final total CVEs in dataset: {len(final_data):,}")
        print(f"📈 Coverage: {len(final_data)/total_cve_files*100:.2f}% of available CVEs")
        print(f"💾 Saved to: {json_file}")
        print(f"⏰ End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}\n")
        
    except KeyboardInterrupt:
        print(f"\n\n{'!'*80}")
        print(f"⚠️  INTERRUPTED BY USER")
        print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        current_count = count_cves_in_batches(batches_dir)
        print(f"📊 CVEs processed so far: {current_count:,}")
        print(f"📁 Batch files saved in: {batches_dir}")
        print(f"♻️  You can resume by running this script again")
        print(f"{'!'*80}\n")
        return 1
    except Exception as e:
        print(f"\n\n{'!'*80}")
        print(f"❌ ERROR OCCURRED: {e}")
        print(f"⏰ Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        current_count = get_current_count(json_file)
        print(f"📊 CVEs processed so far: {current_count:,}")
        print(f"{'!'*80}\n")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())
