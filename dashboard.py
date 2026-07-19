import re
from datetime import datetime
from flask import Flask, render_template_string
from collections import Counter

app = Flask(__name__)

LOG_FILE = 'honeypot_logs.txt'

def parse_logs():
    """Read and parse the honeypot log file"""
    events = []
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            logs = f.readlines()
    except FileNotFoundError:
        return events

    for log in logs:
        log = log.strip()
        if not log:
            continue

        event = {
            'timestamp': '',
            'ip': 'Unknown',
            'type': 'UNKNOWN',
            'path': '/',
            'payload': 'N/A',
            'user_agent': 'N/A',
            'severity': 'LOW'
        }

        # Extract timestamp
        parts = log.split('|')
        if len(parts) >= 1:
            event['timestamp'] = parts[0].strip()

        # Extract IP
        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', log)
        if ip_match:
            event['ip'] = ip_match.group(1)

        # Extract request type
        if 'POST Request' in log:
            event['type'] = 'POST'
        elif 'GET Request' in log:
            event['type'] = 'GET'
        elif 'HEAD Request' in log:
            event['type'] = 'HEAD'

        # Extract path
        path_match = re.search(r'Path: (.*?) \|', log)
        if path_match:
            event['path'] = path_match.group(1).strip()

        # Extract payload
        payload_match = re.search(r'Payload: (.*)', log)
        if payload_match:
            event['payload'] = payload_match.group(1).strip()

        # Extract User-Agent
        ua_match = re.search(r'UA: (.*)', log)
        if ua_match:
            event['user_agent'] = ua_match.group(1).strip()

        # Determine severity
        if event['type'] == 'POST' and event['payload'] != 'N/A':
            if 'OR' in event['payload'] or 'SELECT' in event['payload'] or "'" in event['payload']:
                event['severity'] = 'CRITICAL'
            elif 'admin' in event['payload'].lower():
                event['severity'] = 'HIGH'
            else:
                event['severity'] = 'MEDIUM'
        elif event['type'] == 'GET' and ('..' in event['path'] or 'etc' in event['path']):
            event['severity'] = 'HIGH'
        elif event['type'] == 'HEAD':
            event['severity'] = 'LOW'
        else:
            event['severity'] = 'MEDIUM'

        events.append(event)

    return events


def get_chart_data(events):
    """Prepare data for charts"""
    # Request types count
    type_counts = Counter(e['type'] for e in events)
    
    # Top IPs
    ip_counts = Counter(e['ip'] for e in events)
    top_ips = ip_counts.most_common(5)
    
    # Severity distribution
    severity_counts = Counter(e['severity'] for e in events)
    
    # Attacks over time (by hour)
    time_data = {}
    for e in events:
        if e['timestamp']:
            try:
                dt = datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S')
                hour_key = dt.strftime('%H:%M')
                time_data[hour_key] = time_data.get(hour_key, 0) + 1
            except:
                pass
    
    # Sort by time
    sorted_times = sorted(time_data.keys())
    time_labels = sorted_times[-10:] if len(sorted_times) > 10 else sorted_times
    time_values = [time_data[t] for t in time_labels]
    
    return {
        'type_counts': dict(type_counts),
        'top_ips': top_ips,
        'severity_counts': dict(severity_counts),
        'time_labels': time_labels,
        'time_values': time_values
    }


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot Admin Command Center</title>
    <meta http-equiv="refresh" content="15">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e17 0%, #0d1117 100%);
            color: #e0e0e0;
            min-height: 100vh;
        }

        .header {
            background: linear-gradient(135deg, #1a1f2e, #0d1117);
            border-bottom: 3px solid #00ff88;
            padding: 25px 40px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 4px 20px rgba(0, 255, 136, 0.1);
        }

        .header h1 {
            color: #00ff88;
            font-size: 32px;
            text-shadow: 0 0 15px rgba(0, 255, 136, 0.4);
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .header-right {
            display: flex;
            align-items: center;
            gap: 25px;
        }

        .threat-level {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 20px;
            background: rgba(255, 71, 87, 0.1);
            border: 2px solid #ff4757;
            border-radius: 8px;
        }

        .threat-level.low {
            background: rgba(0, 255, 136, 0.1);
            border-color: #00ff88;
        }

        .threat-level.medium {
            background: rgba(255, 165, 2, 0.1);
            border-color: #ffa502;
        }

        .threat-level.high {
            background: rgba(255, 71, 87, 0.1);
            border-color: #ff4757;
        }

        .threat-level.critical {
            background: rgba(255, 0, 0, 0.15);
            border-color: #ff0000;
            animation: threatPulse 1.5s infinite;
        }

        @keyframes threatPulse {
            0%, 100% { box-shadow: 0 0 10px rgba(255, 0, 0, 0.3); }
            50% { box-shadow: 0 0 25px rgba(255, 0, 0, 0.6); }
        }

        .threat-label {
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
        }

        .threat-value {
            font-size: 18px;
            font-weight: bold;
            color: #fff;
        }

        .status-indicator {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 14px;
            color: #00ff88;
        }

        .status-dot {
            width: 12px;
            height: 12px;
            background-color: #00ff88;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; box-shadow: 0 0 5px #00ff88; }
            50% { opacity: 0.5; box-shadow: 0 0 15px #00ff88; }
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 30px 40px;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: linear-gradient(145deg, #1a1f2e, #141824);
            border: 1px solid #2a2f3e;
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
        }

        .stat-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, transparent, #00ff88, transparent);
        }

        .stat-card:hover {
            transform: translateY(-5px);
            border-color: #00ff88;
            box-shadow: 0 8px 25px rgba(0, 255, 136, 0.15);
        }

        .stat-card .icon {
            font-size: 36px;
            margin-bottom: 10px;
        }

        .stat-card .number {
            font-size: 48px;
            font-weight: bold;
            margin-bottom: 8px;
        }

        .stat-card .label {
            font-size: 13px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .stat-total .number { color: #00bfff; }
        .stat-ips .number { color: #ff6b6b; }
        .stat-post .number { color: #ff4757; }
        .stat-get .number { color: #ffa502; }
        .stat-critical .number { color: #ff0000; }

        .charts-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }

        .chart-card {
            background: linear-gradient(145deg, #1a1f2e, #141824);
            border: 1px solid #2a2f3e;
            border-radius: 12px;
            padding: 25px;
        }

        .chart-title {
            color: #00ff88;
            font-size: 18px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .chart-container {
            position: relative;
            height: 300px;
        }

        .section-title {
            color: #00ff88;
            font-size: 22px;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #2a2f3e;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .table-container {
            background: linear-gradient(145deg, #1a1f2e, #141824);
            border: 1px solid #2a2f3e;
            border-radius: 12px;
            overflow: hidden;
            margin-bottom: 30px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        thead {
            background: #1a1f2e;
        }

        th {
            padding: 15px 20px;
            text-align: left;
            color: #00ff88;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 2px solid #2a2f3e;
        }

        td {
            padding: 14px 20px;
            border-bottom: 1px solid #1e2333;
            font-size: 14px;
            font-family: 'Consolas', 'Courier New', monospace;
        }

        tr:hover {
            background-color: #1a1f2e;
        }

        .badge {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
            display: inline-block;
        }

        .badge-get {
            background: rgba(255, 165, 2, 0.15);
            color: #ffa502;
            border: 1px solid rgba(255, 165, 2, 0.3);
        }

        .badge-post {
            background: rgba(255, 71, 87, 0.15);
            color: #ff4757;
            border: 1px solid rgba(255, 71, 87, 0.3);
        }

        .badge-head {
            background: rgba(0, 191, 255, 0.15);
            color: #00bfff;
            border: 1px solid rgba(0, 191, 255, 0.3);
        }

        .severity-badge {
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
        }

        .severity-low {
            background: rgba(0, 255, 136, 0.15);
            color: #00ff88;
        }

        .severity-medium {
            background: rgba(255, 165, 2, 0.15);
            color: #ffa502;
        }

        .severity-high {
            background: rgba(255, 107, 107, 0.15);
            color: #ff6b6b;
        }

        .severity-critical {
            background: rgba(255, 0, 0, 0.2);
            color: #ff0000;
            animation: criticalBlink 1s infinite;
        }

        @keyframes criticalBlink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }

        .payload-cell {
            color: #ff6b6b;
            max-width: 400px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .ip-cell {
            color: #00bfff;
        }

        .empty-state {
            text-align: center;
            padding: 80px;
            color: #555;
            font-size: 18px;
        }

        .footer {
            text-align: center;
            padding: 30px;
            color: #444;
            font-size: 12px;
            border-top: 1px solid #2a2f3e;
            margin-top: 40px;
        }

        @media (max-width: 1200px) {
            .charts-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Honeypot Admin Command Center</h1>
        <div class="header-right">
            <div class="threat-level {{ threat_class }}">
                <div>
                    <div class="threat-label">Threat Level</div>
                    <div class="threat-value">{{ threat_level }}</div>
                </div>
            </div>
            <div class="status-indicator">
                <div class="status-dot"></div>
                <span>LIVE MONITORING</span>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="stats-grid">
            <div class="stat-card stat-total">
                <div class="icon">📊</div>
                <div class="number">{{ total_events }}</div>
                <div class="label">Total Events</div>
            </div>
            <div class="stat-card stat-ips">
                <div class="icon">🌍</div>
                <div class="number">{{ unique_ips }}</div>
                <div class="label">Unique Attackers</div>
            </div>
            <div class="stat-card stat-post">
                <div class="icon">🎯</div>
                <div class="number">{{ post_count }}</div>
                <div class="label">POST Attacks</div>
            </div>
            <div class="stat-card stat-get">
                <div class="icon">🔍</div>
                <div class="number">{{ get_count }}</div>
                <div class="label">GET Requests</div>
            </div>
            <div class="stat-card stat-critical">
                <div class="icon">⚠️</div>
                <div class="number">{{ critical_count }}</div>
                <div class="label">Critical Threats</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-card">
                <div class="chart-title">📈 Attack Timeline</div>
                <div class="chart-container">
                    <canvas id="timelineChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <div class="chart-title">🎯 Request Types</div>
                <div class="chart-container">
                    <canvas id="typeChart"></canvas>
                </div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-card">
                <div class="chart-title">🏆 Top Attacker IPs</div>
                <div class="chart-container">
                    <canvas id="ipChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <div class="chart-title">⚡ Threat Severity</div>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
        </div>

        <h2 class="section-title">📋 Live Event Stream</h2>

        <div class="table-container">
            {% if events %}
            <table>
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Attacker IP</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Path</th>
                        <th>Payload</th>
                    </tr>
                </thead>
                <tbody>
                    {% for event in events %}
                    <tr>
                        <td>{{ event.timestamp }}</td>
                        <td class="ip-cell">{{ event.ip }}</td>
                        <td>
                            {% if event.type == 'GET' %}
                                <span class="badge badge-get">GET</span>
                            {% elif event.type == 'POST' %}
                                <span class="badge badge-post">POST</span>
                            {% else %}
                                <span class="badge badge-head">HEAD</span>
                            {% endif %}
                        </td>
                        <td>
                            <span class="severity-badge severity-{{ event.severity|lower }}">
                                {{ event.severity }}
                            </span>
                        </td>
                        <td>{{ event.path }}</td>
                        <td class="payload-cell">{{ event.payload }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="empty-state">
                🛡️ No events captured yet. Start your honeypot and generate some traffic!
            </div>
            {% endif %}
        </div>
    </div>

    <div class="footer">
        Honeypot Admin Command Center v2.0 | Real-time Threat Intelligence Dashboard | Auto-refresh: 15s
    </div>

    <script>
        // Chart.js configuration
        Chart.defaults.color = '#888';
        Chart.defaults.borderColor = '#2a2f3e';

        // Timeline Chart
        new Chart(document.getElementById('timelineChart'), {
            type: 'line',
            data: {
                labels: {{ chart_data.time_labels|tojson }},
                datasets: [{
                    label: 'Events',
                    data: {{ chart_data.time_values|tojson }},
                    borderColor: '#00ff88',
                    backgroundColor: 'rgba(0, 255, 136, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointBackgroundColor: '#00ff88',
                    pointBorderColor: '#00ff88',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: '#00ff88'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1 }
                    }
                }
            }
        });

        // Request Types Chart
        new Chart(document.getElementById('typeChart'), {
            type: 'doughnut',
            data: {
                labels: {{ chart_data.type_counts.keys()|list|tojson }},
                datasets: [{
                    data: {{ chart_data.type_counts.values()|list|tojson }},
                    backgroundColor: [
                        '#ffa502',
                        '#ff4757',
                        '#00bfff',
                        '#00ff88'
                    ],
                    borderColor: '#141824',
                    borderWidth: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { padding: 15 }
                    }
                }
            }
        });

        // Top IPs Chart
        new Chart(document.getElementById('ipChart'), {
            type: 'bar',
            data: {
                labels: {{ chart_data.top_ips|map(attribute=0)|list|tojson }},
                datasets: [{
                    label: 'Requests',
                    data: {{ chart_data.top_ips|map(attribute=1)|list|tojson }},
                    backgroundColor: 'rgba(0, 191, 255, 0.6)',
                    borderColor: '#00bfff',
                    borderWidth: 2,
                    borderRadius: 6
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: { stepSize: 1 }
                    }
                }
            }
        });

        // Severity Chart
        new Chart(document.getElementById('severityChart'), {
            type: 'polarArea',
            data: {
                labels: {{ chart_data.severity_counts.keys()|list|tojson }},
                datasets: [{
                    data: {{ chart_data.severity_counts.values()|list|tojson }},
                    backgroundColor: [
                        'rgba(0, 255, 136, 0.6)',
                        'rgba(255, 165, 2, 0.6)',
                        'rgba(255, 107, 107, 0.6)',
                        'rgba(255, 0, 0, 0.6)'
                    ],
                    borderColor: '#141824',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { padding: 15 }
                    }
                }
            }
        });
    </script>
</body>
</html>
"""


@app.route('/')
def dashboard():
    events = parse_logs()
    chart_data = get_chart_data(events)

    # Calculate statistics
    total_events = len(events)
    unique_ips = len(set(e['ip'] for e in events))
    post_count = sum(1 for e in events if e['type'] == 'POST')
    get_count = sum(1 for e in events if e['type'] == 'GET')
    critical_count = sum(1 for e in events if e['severity'] == 'CRITICAL')

    # Determine overall threat level
    if critical_count > 5:
        threat_level = 'CRITICAL'
        threat_class = 'critical'
    elif critical_count > 0 or post_count > 10:
        threat_level = 'HIGH'
        threat_class = 'high'
    elif post_count > 3:
        threat_level = 'MEDIUM'
        threat_class = 'medium'
    else:
        threat_level = 'LOW'
        threat_class = 'low'

    # Reverse events so newest appear first
    events.reverse()

    return render_template_string(
        HTML_TEMPLATE,
        events=events,
        total_events=total_events,
        unique_ips=unique_ips,
        post_count=post_count,
        get_count=get_count,
        critical_count=critical_count,
        threat_level=threat_level,
        threat_class=threat_class,
        chart_data=chart_data
    )


if __name__ == '__main__':
    print("=========================================")
    print("  Honeypot Admin Command Center")
    print("  Open: http://localhost:5000")
    print("=========================================")
    app.run(host='0.0.0.0', port=5000, debug=False)