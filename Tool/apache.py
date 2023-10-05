import advertools as adv
import pandas as pd
from flask import Flask, render_template, request, send_from_directory, redirect, url_for, flash
from flask_session import Session
import os
import plotly.express as px
import hashlib
from loguru import logger
import re
import plotly.graph_objs as go

app = Flask(__name__)
app.secret_key = "SECRET_KEY_INTERESTING"
app.config['SESSION_TYPE'] = 'filesystem'
MAX_FILE_SIZE = 10*1024*1024
Session(app)

ALLOWED_EXTENSIONS = {'txt', 'log'}
app.config['UPLOAD_FOLDER'] = './uploads'

pd.set_option('display.max_columns', None)
pd.set_option('display.max_rows', None)


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


def allowed_file(filename):
    parts = filename.split('.')
    if (len(parts) > 1):
        file_extension = filename.split('.')[-1].lower()
        return file_extension in ALLOWED_EXTENSIONS
    return True


def create_df(log_file_path):
    log_format = detect_log_format(log_file_path)
    logger.info(f'Detected log format: {log_format}')
    os.system('rm -rf access_logs.parquet log_errors.csv')
    adv.logs_to_df(log_file=log_file_path,
                   output_file='access_logs.parquet',
                   errors_file='log_errors.csv',
                   log_format=log_format,
                   fields=None)

    logs_df = pd.read_parquet('access_logs.parquet')
    logs_df['datetime'] = pd.to_datetime(logs_df['datetime'],
                                         format='%d/%b/%Y:%H:%M:%S %z')

    logs_df['datetime'] = logs_df['datetime'].dt.strftime('%d/%b/%Y:%H:%M:%S')

    visitors_in_hour = logs_df.groupby('datetime').size()

    max_points_to_display = 1000  # Adjust this as needed

    step_size = max(len(visitors_in_hour) // max_points_to_display, 1)

    return logs_df, visitors_in_hour, step_size


def generate_random_filename(content):
    return hashlib.md5(content).hexdigest()


def requested_files(max_points_to_display, logs_df):
    requested_files_count = logs_df.groupby(
        ['request', 'method']).size().reset_index(name='count')
    requested_files_count = requested_files_count.sort_values(
        by='count', ascending=False)
    fig = px.bar(requested_files_count.head(max_points_to_display), x='request', y='count', color='method',
                 labels={'request': 'Request', 'count': 'Number of Requests', 'method': 'Method'})
    return fig.to_json()


@app.route('/', methods=['GET', 'POST'])
def dashboard():
    if request.method == 'POST':
        f = request.files['file']
        if f and allowed_file(f.filename):
            content = f.read()
            f.seek(0)
            random_filename = generate_random_filename(content)
            extension = 'txt'
            new_filename = random_filename + '.' + extension
            print(new_filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
            return redirect(f"/reports/{random_filename}")
        if f:
            if len(f.read()) >= MAX_FILE_SIZE:
                error = f"File size limit exceeded"
            else:
                error = f"File extension {f.filename.split('.')[-1]} not supported."
        else:
            error = "File not found."
        return render_template('dashboard.html', error=error)
    error = flash('error')
    print("error: ", error)
    return render_template('dashboard.html', error=error)


@app.route('/uploads/<filename>')
def serve_file(filename):
    return send_from_directory('./uploads', filename)


@app.route('/reports/<report>', methods=['GET'])
def reports(report):
    flag = 0
    for filename in os.listdir('./uploads'):
        if os.path.splitext(filename)[0] == report:
            flag = 1
            file_extension = os.path.splitext(filename)[1].lower()
            break
    if (not flag):
        return "<script>document.location='/'</script>"
    full_name = report + file_extension
    log_file_path = f'./uploads/{full_name}'
    logs_df, visitors_in_hour, step_size = create_df(log_file_path)
    log_format = detect_log_format(log_file_path)
    max_points_to_display = 1000
    columns = logs_df.columns.tolist()
    logs_json = logs_df.to_json(orient='records', date_format='iso')

    trace = go.Scatter(
        x=visitors_in_hour.index[::-1][::step_size],
        y=visitors_in_hour.values[::-1][::step_size],
        mode='lines+markers',
        fill='tozeroy',
        line=dict(shape='spline', smoothing=1.3),
        marker=dict(size=8, symbol='circle')
    )

    fig = go.Figure(data=[trace])

    initial_range = [
        visitors_in_hour.index[0],
        visitors_in_hour.index[len(visitors_in_hour) // 3]
    ]

    fig.update_xaxes(
        rangeslider=dict(
            visible=True,
            range=initial_range
        )
    )

    visitors_per_hour = fig.to_json()

    requested_files_chart = requested_files(max_points_to_display, logs_df)

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
    app.run(debug=True, port=3000)
    os.system('rm -rf access_logs.parquet log_errors.csv')
