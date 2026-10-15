**Log-Based Threat Detection System**

## About the Project

I developed this project using Python to identify suspicious activities in server log files. The idea behind this project is to make it easier to analyze logs and find patterns that may indicate possible security threats.

Instead of checking every log entry manually, the system uses predefined rules to detect suspicious requests and display alerts through a dashboard.

## Features

- Load and analyze server log files
- Detect suspicious patterns such as SQL injection, XSS, and directory traversal
- Monitor log files in real time
- Display security alerts and threat statistics on a dashboard
- Check IP addresses against a local IOC list
- Generate PDF and CSV reports
- Create a list of suspicious IP addresses for review

## Technologies Used

- Python
- Tkinter for the desktop interface
- Regular Expressions for threat detection
- Matplotlib for charts
- JSON and CSV for handling data
- ReportLab for PDF reports

## How to Run

1. Download or clone this repository.
2. Open the project folder in your terminal.
3. Install the required packages:

   `pip install -r requirements.txt`

4. Start the application:

   `python main.py`

## How It Works

The user loads a log file, and the system reads its entries and checks them against predefined detection rules. When a suspicious pattern is found, an alert is generated and the details are shown on the dashboard. The results can also be exported as reports.

## What I Learned

While working on this project, I gained practical experience with Python, log file analysis, pattern matching, and basic cybersecurity concepts. It also helped me understand how automated detection can make security monitoring easier.

## Future Improvements

In the future, I would like to explore machine learning for threat detection and improve the system's accuracy and integration with other security tools.
