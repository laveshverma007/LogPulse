import re
import sys
from flask import Flask, render_template

app = Flask(__name__)

# Function to parse Nginx log file and return data in tabular form
def parse_nginx_log(log_file):
    log_entries = []
    
    # Define a regular expression pattern to match Nginx log format
    log_pattern = r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
    
    with open(log_file, 'r') as f:
        for line in f:
            match = re.match(log_pattern, line)
            if match:
                log_entries.append(match.groups())
    
    return log_entries

# Route to display the Nginx log in a tabular format
@app.route('/')
def nginx_log():
    log_file = sys.argv[1]  # Path to your Nginx log file
    log_entries = parse_nginx_log(log_file)
    return render_template('nginx.html', log_entries=log_entries)

if __name__ == '__main__':
    app.run(debug=True)
