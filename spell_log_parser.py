import re
import pandas as pd
from datetime import datetime

def parse_ssh_log_entry(log_entry):
    """
    Parse a single SSH/auth log entry into structured components
    Handles formats like:
    Jun 14 15:16:01 combo sshd(pam_unix)[19939]: authentication failure; logname= uid=0 euid=0 tty=NODEVssh ruser= rhost=218.188.2.4
    """
    # Main pattern for syslog format
    syslog_pattern = r'^(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(\S+)\s(\S+?)\[(\d+)\]:\s(.*)$'
    
    match = re.match(syslog_pattern, log_entry)
    if not match:
        return None
    
    timestamp, host, process, pid, message = match.groups()
    
    # Parse timestamp (assuming current year)
    try:
        log_time = datetime.strptime(f"{datetime.now().year} {timestamp}", "%Y %b %d %H:%M:%S")
    except ValueError:
        log_time = timestamp  # fallback to raw string
    
    # Parse message components
    message_parts = message.split(';')
    main_message = message_parts[0].strip()
    details = {}
    
    for part in message_parts[1:]:
        # Handle key=value pairs
        for kv in part.split():
            if '=' in kv:
                key, *value = kv.split('=')
                details[key.strip()] = '='.join(value).strip()
    
    return {
        'timestamp': log_time,
        'host': host,
        'process': process,
        'pid': int(pid) if pid.isdigit() else pid,
        'main_message': main_message,
        'details': details,
        'raw': log_entry
    }

def load_and_parse_logs(file_path):
    """Load .log file and parse all entries"""
    parsed_logs = []
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line:  # skip empty lines
                parsed = parse_ssh_log_entry(line)
                if parsed:
                    parsed_logs.append(parsed)
    
    return pd.DataFrame(parsed_logs)

# Example usage
if __name__ == "__main__":
    log_df = load_and_parse_logs("Linux.log.txt")
    print(f"Parsed {len(log_df)} log entries")
    print("\nSample parsed entries:")
    print(log_df.head(3).to_string())
    
    # Save parsed logs to CSV
    log_df.to_csv("parsed.csv", index=False)
    print("\nSaved to parsed_logs.csv")