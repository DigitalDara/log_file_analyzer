""" A script that will analyze log files, and generate a report in either plain text, JSON, and XML. """
"""
    Description
        - The script will read the 'server.log' file within the set path.
        It will search for terms like "Error","Warning" and "Info" within the .log file. 
        Once the terms are found the script will extract the entries for the search term
        in a security report that has been converted to a plain text, JSON, and XML file. 

    Author:
        -Name: Dara Pok
        -Date: 2025-03-30
    
    Assumptions:
        - [Reading File]: Will able to read the file that is set in the SUBDIRECTORY_PATH. If file not found and error will appear. 
        - [Search Pattern]: A user will enter the prompted search pattern that is displayed within the menu GUI. 
        - [File Log Analyzer]: The script will then analyze the search terms within the file to see if they're any matches. 
        - [Report Generater:]: If there are search terms within the file, the script will then generate a report with the incidents.
        - [Save File]: Save the results into a plain text, JSON, and XML file. 
    
    Pseudo Code:
        - Need to set the environment variables, subpath, and filename.
        - Define a read_file function, that will allow to read the file within that path. 
        - Define a detect_security_incidents function that will find the terms ERROR, WARNING, INFO, timestamps etc.
        - Define a filter_incidents_by_level that will filter incidents based on log level (INFO, WARNING, or ERROR).
        - Define a generate_report function that will take the stripped values.
        - Define a save_report function that will take the values and convert it in text with a plain text, JSON, and XML file into the output folder. 


"""

# security_log_file_analyzer.py

import os
import re
import json
import xml.etree.ElementTree as ET

# Environment variables & paths
ENVIRONMENT_VARIABLE = 'COMI_1170_HOME'
INPUT_SUBDIR = 'lessons/resources/lesson04/in'
OUTPUT_SUBDIR = 'lessons/resources/lesson04/out'
FILENAME = 'server.log'

def read_file():
    """Reads the log file and returns its content."""
    comi_home = os.getenv(ENVIRONMENT_VARIABLE)
    if not comi_home:
        print(f"Error: The environment variable '{ENVIRONMENT_VARIABLE}' is not set.")
        return None

    file_path = os.path.join(comi_home, INPUT_SUBDIR, FILENAME)

    if not os.path.exists(file_path):
        print(f"Error: File does not exist: {file_path}")
        return None

    try:
        with open(file_path, 'r') as file:
            return file.readlines()
    except IOError as e:
        print(f"Error reading file: {e}")
        return None

def detect_security_incidents(contents):
    """Identifies security incidents from log contents and returns incident details."""
    incidents = []

    for line in contents:
        timestamp = line.split(" ")[0] + " " + line.split(" ")[1]

        # Determine the log level (INFO, WARNING, ERROR)
        if " INFO " in line:
            log_level = "INFO"
        elif " WARNING " in line:
            log_level = "WARNING"
        elif " ERROR " in line:
            log_level = "ERROR"
        else:
            continue  # Skip lines that do not match

        # Extract user/IP information (assumes the format "User <username> ... from IP <ip>")
        user_match = re.search(r"User (\w+)", line)
        ip_match = re.search(r"IP (\d+\.\d+\.\d+\.\d+)", line)

        user_or_ip = user_match.group(1) if user_match else "Unknown"
        ip_address = ip_match.group(1) if ip_match else "Unknown"

        incidents.append({
            "timestamp": timestamp,
            "log_level": log_level,
            "user_or_ip": user_or_ip,
            "ip_address": ip_address,
            "message": line.strip()
        })

    return incidents

def filter_incidents_by_level(incidents, search_level):
    """Filters incidents based on log level (INFO, WARNING, or ERROR)."""
    return [incident for incident in incidents if incident["log_level"] == search_level]

def generate_report(incidents, log_level):
    """Creates a security report with incident summary."""
    if not incidents:
        return f"--- {log_level} Incident Report ---\nNo incidents detected."

    # Count total incidents
    total_incidents = len(incidents)
    report_lines = [f"--- {log_level} Incident Report ---"]
    report_lines.append(f"Total {log_level} Incidents: {total_incidents}")
    report_lines.append("")  # Blank line for spacing

    # Generate detailed report section
    for incident in incidents:
        report_lines.append(f"Timestamp: {incident['timestamp']}")
        report_lines.append(f"User/IP: {incident['user_or_ip']}")
        report_lines.append(f"IP Address: {incident['ip_address']}")
        report_lines.append(f"Message: {incident['message']}")
        report_lines.append("-------------------------------")

    return "\n".join(report_lines)

def save_report(incidents, report_text, filename_prefix):
    """Saves reports in text, JSON, and XML formats with a given filename prefix."""
    comi_home = os.getenv(ENVIRONMENT_VARIABLE)
    if not comi_home:
        print(f"Error: The environment variable '{ENVIRONMENT_VARIABLE}' is not set.")
        return

    output_path = os.path.join(comi_home, OUTPUT_SUBDIR)
    os.makedirs(output_path, exist_ok=True)

    # Save as plain text
    with open(os.path.join(output_path, f"{filename_prefix}_report.txt"), "w") as file:
        file.write(report_text)

    # Save as JSON
    with open(os.path.join(output_path, f"{filename_prefix}_report.json"), "w") as file:
        json.dump({"total_incidents": len(incidents), "incidents": incidents}, file, indent=4)

    # Save as XML
    root = ET.Element("SecurityIncidents")
    root.set("total_incidents", str(len(incidents)))  # Add total count as an attribute
    for incident in incidents:
        incident_element = ET.SubElement(root, "Incident")
        ET.SubElement(incident_element, "Timestamp").text = incident["timestamp"]
        ET.SubElement(incident_element, "LogLevel").text = incident["log_level"]
        ET.SubElement(incident_element, "UserOrIP").text = incident["user_or_ip"]
        ET.SubElement(incident_element, "IPAddress").text = incident["ip_address"]
        ET.SubElement(incident_element, "Message").text = incident["message"]

    tree = ET.ElementTree(root)
    with open(os.path.join(output_path, f"{filename_prefix}_report.xml"), "wb") as file:
        tree.write(file)

    print(f"\nReports for '{filename_prefix}' saved in: {output_path}")

def main():
    """Main script execution with log level filtering."""
    contents = read_file()
    if contents is None:
        return

    incidents = detect_security_incidents(contents)

    # Ask user for search terms (must be INFO, WARNING, or ERROR)
    while True:
        search_terms = input("Enter log levels to search (INFO, WARNING, ERROR) separated by commas: ").upper().split(",")
        search_terms = [term.strip() for term in search_terms if term.strip() in ["INFO", "WARNING", "ERROR"]]

        if not search_terms:
            print("Invalid input. Please enter only INFO, WARNING, or ERROR.")
        else:
            break

    for term in search_terms:
        filtered_incidents = filter_incidents_by_level(incidents, term)
        report_text = generate_report(filtered_incidents, term)

        if filtered_incidents:
            filename_prefix = f"search_{term}"
            save_report(filtered_incidents, report_text, filename_prefix)
        else:
            print(f"No incidents found for log level: {term}")

if __name__ == "__main__":
    main()
