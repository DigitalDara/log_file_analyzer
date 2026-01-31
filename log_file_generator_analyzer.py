""" A script that will randomnly generate security logs, analyze, and generate report in a exported file. """
"""
    Description
        - This script automates the generation and analysis of simulated IDS/IPS log data. 
        It reads configuration values from text files, generates 10,000–20,000 random log entries, 
        and analyzes the logs to produce summary reports in plain text, JSON, and XML formats.

    Author:
        -Name: Dara Pok
        -Date: May 4th, 2025
    
    Assumptions:
        - All configuration .txt files exist in the specified input directory and contain one entry per line.
        - The environment path is correctly set to resolve input and output directories using COMI_1170_HOME or a relative path.
        - Each log entry follows a consistent format that can be parsed for analysis.
        - Users have read/write permissions in the input and output directories.
    
    Pseudo Code:
        - Read all config files (alert types, protocols, IPs, etc.) into memory.
        - Generate a random number of log entries using combinations of config values and timestamps.
        - Write the generated logs to a single log file.
        - Read the log file line-by-line and extract key data (e.g., security level, alert type, IPs).
        - Count occurrences and aggregate data into categories.
        - Output analysis results into .txt, .json, and .xml report files.
   
    Observations:
        - The log format remains consistent across all entries, which simplifies parsing.
        - Handling missing or empty config files gracefully prevents crashes.
        - JSON and XML formats provide machine-readable reports suitable for integration with other systems.
        - The script runs fully automated without user input, ideal for batch processing or cron jobs.


"""

# Your script content goes here

import os
import random
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

# Directory setup
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "wsl", "comi1170-shared"))
INPUT_DIR = os.path.join(BASE_DIR, "lessons/resources/lesson06/in")
OUTPUT_DIR = os.path.join(BASE_DIR, "lessons/resources/lesson06/out")
LOG_FILE = os.path.join(OUTPUT_DIR, "generated_logs.txt")

# Report files
TXT_REPORT = os.path.join(OUTPUT_DIR, "log_analysis.txt")
JSON_REPORT = os.path.join(OUTPUT_DIR, "log_analysis.json")
XML_REPORT = os.path.join(OUTPUT_DIR, "log_analysis.xml")

# Configuration files
CONFIG_FILES = {
    'alert_types': 'alert_types.txt',
    'protocols': 'protocols.txt',
    'actions': 'actions.txt',
    'ip_addresses': 'ip_addresses.txt',
    'security_levels': 'security_levels.txt',
    'ports': 'ports.txt',
    'timezones': 'timezones.txt'
}

def read_config_file(file_path):
    """Read configuration file and return contents as list"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Config file not found: {file_path}")
    
    with open(file_path, 'r') as file:
        contents = [line.strip() for line in file if line.strip()]
        
    if not contents:
        raise ValueError(f"Config file is empty: {file_path}")
        
    return contents

def load_config_files():
    """Load all configuration files into a dictionary"""
    config_data = {}
    
    for config_type, filename in CONFIG_FILES.items():
        try:
            file_path = os.path.join(INPUT_DIR, filename)
            config_data[config_type] = read_config_file(file_path)
        except Exception as e:
            print(f"⚠️ Could not load {config_type} config: {str(e)}")
            config_data[config_type] = []
            
    return config_data

def generate_log_entry(config_data, timestamp):
    """Generate a single log entry with random values"""
    entry_time = timestamp + timedelta(seconds=random.randint(0, 60))
    
    # Select random values for each field
    alert_type = random.choice(config_data['alert_types'] or ['UNKNOWN'])
    protocol = random.choice(config_data['protocols'] or ['UNKNOWN'])
    action = random.choice(config_data['actions'] or ['UNKNOWN'])
    src_ip = random.choice(config_data['ip_addresses'] or ['0.0.0.0'])
    dst_ip = random.choice(config_data['ip_addresses'] or ['0.0.0.0'])
    security_level = random.choice(config_data['security_levels'] or ['INFO'])
    src_port = random.choice(config_data['ports'] or ['0'])
    dst_port = random.choice(config_data['ports'] or ['0'])
    timezone = random.choice(config_data['timezones'] or ['UTC'])
    
    # Format the log entry
    return (
        f"[{entry_time.strftime('%Y-%m-%d %H:%M:%S')} {timezone}] "
        f"ALERT: {alert_type} "
        f"PROTOCOL: {protocol} "
        f"ACTION: {action} "
        f"SRC_IP: {src_ip}:{src_port} "
        f"DST_IP: {dst_ip}:{dst_port} "
        f"LEVEL: {security_level}"
    )

def generate_logs():
    """Generate log file with random entries"""
    try:
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)

        config_data = load_config_files()
        num_entries = random.randint(10000, 20000)
        base_timestamp = datetime.now()
        
        print(f"🔧 Generating {num_entries} log entries to {LOG_FILE}")
        
        with open(LOG_FILE, 'w') as log_file:
            for i in range(num_entries):
                log_entry = generate_log_entry(config_data, base_timestamp)
                log_file.write(log_entry + '\n')
                
                if i % 1000 == 0 and i > 0:
                    print(f"⏳ Generated {i} entries...")
        
        print(f"✅ Successfully generated {num_entries} log entries")
        return True
    except Exception as e:
        print(f"❌ Error during log generation: {str(e)}")
        return False

def analyze_logs():
    """Analyze generated logs and create reports in multiple formats"""
    try:
        if not os.path.exists(LOG_FILE):
            print("❌ Log file not found. Generate logs first.")
            return False

        # Initialize counters with the actual level names from your logs
        stats = {
            'total_entries': 0,
            'security_levels': {
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Critical': 0
            },
            'alert_types': {},
            'protocols': {},
            'actions': {},
            'source_ips': {},
            'dest_ips': {}
        }

        with open(LOG_FILE, 'r') as log_file:
            for line in log_file:
                stats['total_entries'] += 1
                
                # Parse security level - improved parsing
                if "LEVEL: " in line:
                    level_part = line.split("LEVEL: ")[1]
                    level = level_part.split()[0]  # Get first word after LEVEL:
                    if level in stats['security_levels']:
                        stats['security_levels'][level] += 1
                    else:
                        # Track unexpected levels but don't print to terminal
                        stats['security_levels'][level] = stats['security_levels'].get(level, 0) + 1
                
                # Parse other fields
                if "ALERT: " in line:
                    alert = line.split("ALERT: ")[1].split()[0]
                    stats['alert_types'][alert] = stats['alert_types'].get(alert, 0) + 1
                
                if "PROTOCOL: " in line:
                    proto = line.split("PROTOCOL: ")[1].split()[0]
                    stats['protocols'][proto] = stats['protocols'].get(proto, 0) + 1
                
                if "ACTION: " in line:
                    action = line.split("ACTION: ")[1].split()[0]
                    stats['actions'][action] = stats['actions'].get(action, 0) + 1
                
                if "SRC_IP: " in line:
                    src_ip = line.split("SRC_IP: ")[1].split(':')[0]
                    stats['source_ips'][src_ip] = stats['source_ips'].get(src_ip, 0) + 1
                
                if "DST_IP: " in line:
                    dst_ip = line.split("DST_IP: ")[1].split(':')[0]
                    stats['dest_ips'][dst_ip] = stats['dest_ips'].get(dst_ip, 0) + 1

        # Generate reports
        generate_text_report(stats)
        generate_json_report(stats)
        generate_xml_report(stats)
        
        print(f"✅ Analysis reports generated in {OUTPUT_DIR}")
        return True
    except Exception as e:
        print(f"❌ Error during log analysis: {str(e)}")
        return False

def generate_text_report(stats):
    """Generate text format report with correct level names"""
    report = f"Log Analysis Report\n{'='*40}\n\n"
    report += f"Total Entries: {stats['total_entries']}\n\n"
    
    report += "Security Level Distribution:\n"
    for level, count in stats['security_levels'].items():
        percentage = (count / stats['total_entries']) * 100
        report += f"{level}: {count} ({percentage:.1f}%)\n"
    
    report += "\nTop Alert Types:\n"
    for alert, count in sorted(stats['alert_types'].items(), key=lambda x: x[1], reverse=True)[:10]:
        report += f"{alert}: {count}\n"
    
    report += "\nTop Protocols:\n"
    for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:5]:
        report += f"{proto}: {count}\n"
    
    report += "\nAction Distribution:\n"
    for action, count in stats['actions'].items():
        report += f"{action}: {count}\n"
    
    with open(TXT_REPORT, 'w') as f:
        f.write(report)

def generate_text_report(stats):
    """Generate text format report"""
    report = f"Log Analysis Report\n{'='*40}\n\n"
    report += f"Total Entries: {stats['total_entries']}\n\n"
    
    report += "Security Level Distribution:\n"
    for level, count in stats['security_levels'].items():
        report += f"{level}: {count} ({count/stats['total_entries']:.1%})\n"
    
    report += "\nTop Alert Types:\n"
    for alert, count in sorted(stats['alert_types'].items(), key=lambda x: x[1], reverse=True)[:10]:
        report += f"{alert}: {count}\n"
    
    report += "\nTop Protocols:\n"
    for proto, count in sorted(stats['protocols'].items(), key=lambda x: x[1], reverse=True)[:5]:
        report += f"{proto}: {count}\n"
    
    report += "\nAction Distribution:\n"
    for action, count in stats['actions'].items():
        report += f"{action}: {count}\n"
    
    with open(TXT_REPORT, 'w') as f:
        f.write(report)

def generate_json_report(stats):
    """Generate JSON format report"""
    with open(JSON_REPORT, 'w') as f:
        json.dump(stats, f, indent=2)

def generate_xml_report(stats):
    """Generate XML format report"""
    root = ET.Element('LogAnalysis')
    
    # Add summary
    summary = ET.SubElement(root, 'Summary')
    ET.SubElement(summary, 'TotalEntries').text = str(stats['total_entries'])
    
    # Add security levels
    levels = ET.SubElement(root, 'SecurityLevels')
    for level, count in stats['security_levels'].items():
        elem = ET.SubElement(levels, level)
        elem.text = str(count)
    
    # Add alert types
    alerts = ET.SubElement(root, 'AlertTypes')
    for alert, count in stats['alert_types'].items():
        elem = ET.SubElement(alerts, 'Alert')
        elem.set('type', alert)
        elem.set('count', str(count))
    
    # Write to file
    tree = ET.ElementTree(root)
    tree.write(XML_REPORT, encoding='utf-8', xml_declaration=True)

def main():
    """Main entry point"""
    # Generate logs
    if not generate_logs():
        return
    
    # Analyze logs
    analyze_logs()

if __name__ == '__main__':
    main()