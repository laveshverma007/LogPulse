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
visitors_in_hour = logs_df.groupby('datetime').size()

# Choose the maximum number of points to display on the x-axis
max_points_to_display = 1000  # Adjust this as needed

# Calculate the step size for the x-axis
step_size = max(len(visitors_in_hour) // max_points_to_display, 1)


@app.route('/reports', methods=['GET', 'POST'])
def display_dataframe():
    # Create a Plotly figure for Visitors Per Hour
    columns = logs_df.columns.tolist()
    logs_json = logs_df.to_json(orient='records', date_format='iso')

    trace = go.Scatter(
        x=visitors_in_hour.index[::-1][::step_size],  # Display fewer points
        y=visitors_in_hour.values[::-1][::step_size],  # Display fewer points
        mode='lines+markers',
        fill='tozeroy',
        # Adjust smoothing for curve smoothness
        line=dict(shape='spline', smoothing=1.3),
        marker=dict(size=8, symbol='circle')
    )

    fig = go.Figure(data=[trace])

    # Set the initial x-axis range
    initial_range = [
        visitors_in_hour.index[0],
        visitors_in_hour.index[len(visitors_in_hour) // 3]
    ]

    # Configure the rangeslider
    fig.update_xaxes(
        rangeslider=dict(
            visible=True,
            range=initial_range
        )
    )

    visitors_per_hour = fig.to_json()

    requested_files_count = logs_df.groupby(
        ['request', 'method']).size().reset_index(name='count')
    requested_files_count = requested_files_count.sort_values(
        by='count', ascending=False)
    # Create a bar chart using Plotly Express
    fig = px.bar(requested_files_count.head(max_points_to_display), x='request', y='count', color='method',
                 labels={'request': 'Request', 'count': 'Number of Requests', 'method': 'Method'})
    # fig.update_layout(
    #     title='Top 10 Requested Files and Methods',
    #     xaxis_title='Request',
    #     yaxis_title='Number of Requests',
    #     xaxis_tickangle=-45  # Rotate x-axis labels for better readability
    # )

    # Convert the Plotly figure to JSON
    requested_files_chart = fig.to_json()

    # Convert the Plotly figure to JSON
    # Define a list of file extensions to count
    file_extensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'tiff', 'svg', 'webp',  # Image files
                       'css', 'scss', 'less', 'sass', 'styl',  # Stylesheets
                       'js', 'jsx', 'ts', 'tsx', 'coffee', 'dart',  # Script files
                       'html', 'htm', 'php', 'asp', 'jsp', 'xml', 'xhtml',  # Webpage files
                       'pdf', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx', 'csv', 'txt',  # Document files
                       'mp3', 'wav', 'ogg', 'flac', 'aac', 'wma',  # Audio files
                       'mp4', 'avi', 'wmv', 'flv', 'mkv', 'mov', 'webm',  # Video files
                       # Archive files
                       'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'pkg', 'deb', 'rpm', 'msi', 'dmg',
                       'exe', 'msi', 'bat', 'sh', 'cmd', 'ps1',  # Executable files
                       'json', 'xml', 'yaml', 'yml', 'toml',  # Configuration files
                       'log', 'ini', 'conf', 'cfg', 'env',  # Configuration files
                       # Database and data files
                       'sql', 'db', 'sqlite', 'mdb', 'accdb', 'dbf', 'csv', 'tsv', 'jsonl',
                       'svg', 'eps', 'ps', 'ai',  # Vector graphic files
                       'ttf', 'otf', 'woff', 'woff2', 'eot', 'fon']  # Font files
    num_requested_files = logs_df['request'].str.extract(
        r'(\S+\.(?:' + '|'.join(file_extensions) + r'))', expand=False).nunique()
    total_requests = len(logs_df)

    valid_requests = len(logs_df[logs_df['status'].astype(str).str.startswith(
        '2')]) + len(logs_df[logs_df['status'].astype(str).str.startswith('3')])
    failed_requests = total_requests - valid_requests
    unique_visitors = logs_df['client'].nunique()
    referrers = "" if log_format == 'common' else logs_df[logs_df['referer']
                                                          != '-']['referer'].nunique()
    log_size = os.path.getsize(log_file_path)

    return render_template('apache.html', num_requested_files=num_requested_files, visitors_per_hour=visitors_per_hour, columns=columns, data=logs_json, total_requests=total_requests, valid_requests=valid_requests,
                           failed_requests=failed_requests, unique_visitors=unique_visitors, referrers=referrers,
                           log_size=log_size, requested_files_chart=requested_files_chart)


if __name__ == '__main__':
    app.run(debug=True)
    os.system('rm -rf access_logs.parquet log_errors.csv')
