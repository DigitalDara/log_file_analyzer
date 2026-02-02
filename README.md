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
