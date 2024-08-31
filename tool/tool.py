import threading
import time
from datetime import datetime
from scapy.all import sniff, IP
import pandas as pd
import dash
from dash import dcc, html
import plotly.express as px
import plotly.graph_objs as go
from dash.dependencies import Output, Input
import psutil
import logging
import requests
from collections import defaultdict
import uuid

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Global lists and dictionaries to hold traffic data
traffic_data = []
behavioral_data = []
endpoint_requests = []
ip_block_list = set()
rate_limit_dict = defaultdict(int)

# Thresholds for detection
TRAFFIC_THRESHOLD = 1000
BEHAVIORAL_THRESHOLD = 100
ENDPOINT_THRESHOLD = 500
RATE_LIMIT_THRESHOLD = 100

# Packet callback function for sniffing network traffic
def packet_callback(packet):
    if IP in packet:
        pkt_time = datetime.now()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        pkt_len = len(packet)
        
        # Collect traffic data
        traffic_data.append({
            'timestamp': pkt_time,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'packet_length': pkt_len
        })
        
        # Collect behavioral data (example: geolocation)
        try:
            geo_info = requests.get(f"https://ipapi.co/{src_ip}/json/").json()
            behavioral_data.append({
                'timestamp': pkt_time,
                'src_ip': src_ip,
                'country': geo_info.get('country_name', 'Unknown'),
                'profile': f"{geo_info.get('country_code', 'XX')}_{geo_info.get('org', 'Unknown')}"
            })
        except Exception as e:
            logging.error(f"Error fetching geolocation data: {e}")
        
        # Collect endpoint request data (simulated)
        endpoint = f"/api/endpoint_{uuid.uuid4().hex[:8]}"  # Simulated endpoint
        endpoint_requests.append({
            'timestamp': pkt_time,
            'src_ip': src_ip,
            'endpoint': endpoint
        })
        
        # Apply rate limiting
        rate_limit_dict[src_ip] += 1
        if rate_limit_dict[src_ip] > RATE_LIMIT_THRESHOLD:
            logging.warning(f"Rate limit exceeded for IP: {src_ip}")
            # Implement rate limiting logic here (e.g., temporarily block the IP)

# Function to start sniffing network traffic
def start_sniffing(interface):
    try:
        sniff(iface=interface, prn=packet_callback, store=False)
    except Exception as e:
        logging.error(f"Error starting sniffing: {e}")

# Function to create a DataFrame from traffic data
def create_dataframe(data):
    try:
        df = pd.DataFrame(data)
        df.dropna(inplace=True)  # Drop rows with missing values if any
        
        # Ensure DataFrame columns are correctly aligned
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df.set_index('timestamp', inplace=True)
        
        return df
    except ValueError as e:
        logging.error(f"Error creating DataFrame: {e}")
        return pd.DataFrame()

# Function to detect suspicious traffic from a single IP
def detect_suspicious_traffic():
    df = create_dataframe(traffic_data)
    if df.empty or 'src_ip' not in df.columns:
        return []

    traffic_summary = df.groupby('src_ip').size()
    suspicious_ips = traffic_summary[traffic_summary > TRAFFIC_THRESHOLD].index.tolist()
    return suspicious_ips

# Function to detect flood of traffic with shared behavioral profile
def detect_behavioral_flood():
    df = create_dataframe(behavioral_data)
    if df.empty or 'profile' not in df.columns:
        return []

    behavioral_summary = df.groupby('profile').size()
    suspicious_profiles = behavioral_summary[behavioral_summary > BEHAVIORAL_THRESHOLD].index.tolist()
    return suspicious_profiles

# Function to detect surge in requests to a single endpoint
def detect_endpoint_surge():
    df = create_dataframe(endpoint_requests)
    if df.empty or 'endpoint' not in df.columns:
        return []

    endpoint_summary = df.groupby('endpoint').size()
    surge_endpoints = endpoint_summary[endpoint_summary > ENDPOINT_THRESHOLD].index.tolist()
    return surge_endpoints

# Function to detect odd traffic patterns
def detect_odd_patterns():
    df = create_dataframe(traffic_data)
    if df.empty:
        return []

    df_resampled = df.resample('h').size().to_frame(name='count')  # Updated to 'h'
    hourly_counts = df_resampled['count']
    mean = hourly_counts.mean()
    std = hourly_counts.std()
    hourly_spikes = hourly_counts[hourly_counts > mean + 3 * std]
    
    spike_patterns = hourly_spikes.index.tolist()
    return spike_patterns

# Function to mitigate detected threats
def mitigate_threats(suspicious_ips, suspicious_profiles, surge_endpoints):
    for ip in suspicious_ips:
        if ip not in ip_block_list:
            ip_block_list.add(ip)
            logging.info(f"Blocking suspicious IP: {ip}")
            # Implement actual IP blocking logic here (e.g., update firewall rules)
    
    for profile in suspicious_profiles:
        logging.info(f"Implementing additional verification for profile: {profile}")
        # Implement additional verification steps for suspicious profiles
    
    for endpoint in surge_endpoints:
        logging.info(f"Implementing rate limiting for endpoint: {endpoint}")
        # Implement rate limiting for specific endpoints

# Function to analyze traffic and detect anomalies
def analyze_traffic():
    global traffic_data, behavioral_data, endpoint_requests
    while True:
        if len(traffic_data) > 1000:
            # Detect anomalies
            suspicious_ips = detect_suspicious_traffic()
            suspicious_profiles = detect_behavioral_flood()
            surge_endpoints = detect_endpoint_surge()
            spike_patterns = detect_odd_patterns()
            
            # Mitigate threats
            mitigate_threats(suspicious_ips, suspicious_profiles, surge_endpoints)
            
            # Print or log the findings
            if suspicious_ips or suspicious_profiles or surge_endpoints or spike_patterns:
                logging.warning("Potential DDoS attack detected!")
                if suspicious_ips:
                    logging.info(f"Suspicious IPs: {suspicious_ips}")
                if suspicious_profiles:
                    logging.info(f"Suspicious Behavioral Profiles: {suspicious_profiles}")
                if surge_endpoints:
                    logging.info(f"Surging Endpoints: {surge_endpoints}")
                if spike_patterns:
                    logging.info(f"Odd Traffic Patterns: {spike_patterns}")
                
                # Trigger cloud-based mitigation strategies
                trigger_cloud_mitigation()
            
            # Clear data after analysis
            traffic_data.clear()
            behavioral_data.clear()
            endpoint_requests.clear()
            rate_limit_dict.clear()
        time.sleep(60)  # Analyze every minute

# Function to trigger cloud-based mitigation strategies
def trigger_cloud_mitigation():
    logging.info("Triggering cloud-based mitigation strategies")
    # Placeholder for cloud-specific actions:
    # 1. Scale up resources
    # 2. Activate cloud-based DDoS protection services
    # 3. Redirect traffic through scrubbing centers
    # 4. Implement geoblocking if attack is from specific regions
    # Example: 
    # cloud_provider.scale_up_resources()
    # cloud_provider.activate_ddos_protection()
    # cloud_provider.redirect_traffic_to_scrubbing_center()

# Function to get real-time network statistics
def get_network_stats():
    stats = {}
    net_if_addrs = psutil.net_if_addrs()
    net_if_stats = psutil.net_if_stats()
    
    for iface in net_if_addrs:
        if iface in net_if_stats and net_if_stats[iface].isup:
            stats[iface] = {
                'bytes_sent': psutil.net_io_counters(pernic=True)[iface].bytes_sent,
                'bytes_recv': psutil.net_io_counters(pernic=True)[iface].bytes_recv
            }
    return stats

# Dash web app for live dashboard visualization
app = dash.Dash(__name__)

app.layout = html.Div(children=[
    html.H1(children='DDoS Detection Dashboard'),
    
    html.Div(children=[
        html.Div([
            html.H3('Traffic Overview'),
            dcc.Graph(id='live-traffic'),
        ], className='six columns'),
        
        html.Div([
            html.H3('Network Statistics'),
            dcc.Graph(id='network-stats'),
        ], className='six columns'),
    ], className='row'),
    
    html.Div(children=[
        html.Div([
            html.H3('DDoS Attack Status'),
            html.Div(id='ddos-status'),
        ], className='six columns'),
        
        html.Div([
            html.H3('Suspicious Activities'),
            html.Div(id='suspicious-activities'),
        ], className='six columns'),
    ], className='row'),
    
    html.Div(children=[
        html.H3('Top 10 Source IPs'),
        dcc.Graph(id='top-source-ips'),
    ]),
    
    dcc.Interval(
        id='interval-component',
        interval=5*1000,  # Update every 5 seconds
        n_intervals=0
    )
])

@app.callback(Output('live-traffic', 'figure'),
              Input('interval-component', 'n_intervals'))
def update_graph_live(n):
    df = create_dataframe(traffic_data)
    if df.empty or 'packet_length' not in df.columns:
        return px.scatter(title='No data available')
    
    df = df.reset_index()
    fig = px.scatter(df, x='timestamp', y='packet_length', color='src_ip', title='Live Traffic Data')
    return fig

@app.callback(Output('network-stats', 'figure'),
              Input('interval-component', 'n_intervals'))
def update_network_stats(n):
    stats = get_network_stats()
    if not stats:
        return px.bar(title='No network data available')

    iface_stats = pd.DataFrame(stats).T
    fig = px.bar(iface_stats, x=iface_stats.index, y=['bytes_sent', 'bytes_recv'],
                 title='Network Statistics', labels={'value': 'Bytes', 'index': 'Interface'})
    return fig

@app.callback(Output('ddos-status', 'children'),
              Input('interval-component', 'n_intervals'))
def update_ddos_status(n):
    suspicious_ips = detect_suspicious_traffic()
    suspicious_profiles = detect_behavioral_flood()
    surge_endpoints = detect_endpoint_surge()
    spike_patterns = detect_odd_patterns()

    status = []
    if suspicious_ips:
        status.append(f"Suspicious IPs detected: {suspicious_ips}")
    if suspicious_profiles:
        status.append(f"Suspicious Behavioral Profiles detected: {suspicious_profiles}")
    if surge_endpoints:
        status.append(f"Endpoint Surges detected: {surge_endpoints}")
    if spike_patterns:
        status.append(f"Odd Traffic Patterns detected: {spike_patterns}")
    
    return html.Div([html.P(s) for s in status])

@app.callback(Output('suspicious-activities', 'children'),
              Input('interval-component', 'n_intervals'))
def update_suspicious_activities(n):
    df = create_dataframe(behavioral_data)
    if df.empty:
        return html.P("No suspicious activities detected.")
    
    activities = df[['timestamp', 'src_ip', 'country', 'profile']].tail(10)
    return html.Div([html.P(f"{row['timestamp']}: {row['src_ip']} - {row['country']} ({row['profile']})") for index, row in activities.iterrows()])

@app.callback(Output('top-source-ips', 'figure'),
              Input('interval-component', 'n_intervals'))
def update_top_source_ips(n):
    df = create_dataframe(traffic_data)
    if df.empty or 'src_ip' not in df.columns:
        return px.bar(title='No data available')

    top_ips = df['src_ip'].value_counts().head(10)
    fig = px.bar(top_ips, x=top_ips.index, y=top_ips.values, title='Top 10 Source IPs')
    return fig
if __name__ == '__main__':
    interface = 'en0'  # Change to the appropriate network interface
    sniffing_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniffing_thread.daemon = True
    sniffing_thread.start()
    
    analysis_thread = threading.Thread(target=analyze_traffic)
    analysis_thread.daemon = True
    analysis_thread.start()
    
    app.run_server(debug=True, port=8054)  # Change 8051 to any available port


