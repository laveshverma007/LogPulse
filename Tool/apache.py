import advertools as adv
import pandas as pd
from flask import Flask, render_template
import os
import sys
import plotly.express as px
from loguru import logger
import re   
import plotly.graph_objs as go

app = Flask(__name__)

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)

# Sample log file path
log_file_path = sys.argv[1]

# Function to automatically detect log format
def detect_log_format(log_file_path):
    common_log_pattern = r'^\S+ \S+ \S+ \[[^\]]+\] ".+" \d+ \d+'
    combined_log_pattern = r'^\S+ \S+ \S+ \[[^\]]+\] ".+" \d+ \d+ ".+" ".+"$'

    with open(log_file_path, 'r') as log_file:
        for line in log_file:
            if re.match(combined_log_pattern, line):
                return 'combined'
            elif re.match(common_log_pattern, line):
                return 'common'
    return 'unknown'

log_format = detect_log_format(log_file_path)
logger.info(f'Detected log format: {log_format}')

# Convert the log file to Parquet format
os.system('rm -rf access_logs.parquet log_errors.csv')
adv.logs_to_df(log_file=log_file_path,
               output_file='access_logs.parquet',
               errors_file='log_errors.csv',
               log_format=log_format,  # Automatically detected log format
               fields=None)

logs_df = pd.read_parquet('access_logs.parquet')
logs_df['datetime'] = pd.to_datetime(logs_df['datetime'],
                                     format='%d/%b/%Y:%H:%M:%S %z')

# Create a new column for formatted timestamps
logs_df['datetime'] = logs_df['datetime'].dt.strftime('%d/%b/%Y:%H:%M:%S')

# Calculate Visitors Per Hour
visitors_per_hour = logs_df.groupby('datetime').size()

# Choose the maximum number of points to display on the x-axis
max_points_to_display = 100  # Adjust this as needed

# Calculate the step size for the x-axis
step_size = max(len(visitors_per_hour) // max_points_to_display, 1)

@app.route('/', methods=['GET', 'POST'])
def display_dataframe():
    # Create a Plotly figure for Visitors Per Hour
    columns = logs_df.columns.tolist()
    logs_json = logs_df.to_json(orient='records', date_format='iso')

    trace = go.Scatter(
        x=visitors_per_hour.index[::step_size],  # Display fewer points
        y=visitors_per_hour.values[::step_size],  # Display fewer points
        mode='lines+markers',
        fill='tozeroy',
        line=dict(shape='spline', smoothing=1.3),  # Adjust smoothing for curve smoothness
        marker=dict(size=8, color='rgba(0, 116, 217, 0.7)', symbol='circle'),
    )

    fig = go.Figure(data=[trace])
    fig.update_layout(
        title='Visitors Per Hour',
        xaxis_title='Timestamp',
        yaxis_title='Visitors',
        plot_bgcolor='white'
    )

    # Set the initial x-axis range
    initial_range = [
        visitors_per_hour.index[0],
        visitors_per_hour.index[len(visitors_per_hour) // 3]
    ]

    # Configure the rangeslider
    fig.update_xaxes(
        rangeslider=dict(
            visible=True,
            range=initial_range
        )
    )

    # Convert the Plotly figure to JSON
    chart = fig.to_json()
    # Define a list of file extensions to count
    file_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'tiff', 'svg', 'webp',  # Image files
                   'css', 'scss', 'less', 'sass', 'styl',  # Stylesheets
                   'js', 'jsx', 'ts', 'tsx', 'coffee', 'dart',  # Script files
                   'html', 'htm', 'php', 'asp', 'jsp', 'xml', 'xhtml',  # Webpage files
                   'pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'csv', 'txt',  # Document files
                   'mp3', 'wav', 'ogg', 'flac', 'aac', 'wma',  # Audio files
                   'mp4', 'avi', 'wmv', 'flv', 'mkv', 'mov', 'webm',  # Video files
                   'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'pkg', 'deb', 'rpm', 'msi', 'dmg',  # Archive files
                   'exe', 'msi', 'bat', 'sh', 'cmd', 'ps1',  # Executable files
                   'json', 'xml', 'yaml', 'yml', 'toml',  # Configuration files
                   'log', 'ini', 'conf', 'cfg', 'env',  # Configuration files
                   'sql', 'db', 'sqlite', 'mdb', 'accdb', 'dbf', 'csv', 'tsv', 'jsonl',  # Database and data files
                   'svg', 'eps', 'ps', 'ai',  # Vector graphic files
                   'ttf', 'otf', 'woff', 'woff2', 'eot', 'fon']  # Font files
    num_requested_files = logs_df['request'].str.extract(r'(\S+\.(?:' + '|'.join(file_extensions) + r'))', expand=False).nunique()
    total_requests = len(logs_df)
    valid_requests = len(logs_df[logs_df['status'].astype(str).str.startswith('2')]) + len(logs_df[logs_df['status'].astype(str).str.startswith('3')])
    failed_requests = total_requests - valid_requests
    unique_visitors = logs_df['client'].nunique()
    referrers = "" if log_format == 'common' else logs_df[logs_df['referer'] != '-']['referer'].nunique()
    log_size = os.path.getsize(log_file_path)   

    return render_template('apache.html', num_requested_files=num_requested_files,chart=chart, columns=columns, data=logs_json,total_requests=total_requests, valid_requests=valid_requests,
                       failed_requests=failed_requests, unique_visitors=unique_visitors, referrers=referrers,
                       log_size=log_size)

if __name__ == '__main__':
    app.run(debug=True)
    os.system('rm -rf access_logs.parquet log_errors.csv')
