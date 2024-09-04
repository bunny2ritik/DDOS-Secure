import threading
import time
from datetime import datetime
from scapy.all import sniff, IP
import pandas as pd
import plotly.express as px
import streamlit as st
import psutil
import logging
import requests
from collections import defaultdict
import uuid
import subprocess
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import plotly.graph_objects as go 
import numpy as np
import joblib

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Global lists and dictionaries to hold traffic data
traffic_data = []
behavioral_data = []
endpoint_requests = []
ip_block_list = set()
rate_limit_dict = defaultdict(int)
blocked_traffic_data = []

# Thresholds for detection
TRAFFIC_THRESHOLD = 1000
BEHAVIORAL_THRESHOLD = 100
ENDPOINT_THRESHOLD = 500
RATE_LIMIT_THRESHOLD = 100

# Load or train a machine learning model for anomaly detection
def train_or_load_model():
    try:
        model = joblib.load("ddos_model.pkl")
    except:
        model = IsolationForest(contamination=0.01)
        # Placeholder data with three features for model training
        sample_data = np.random.rand(100, 3)
        model.fit(sample_data)
        joblib.dump(model, "ddos_model.pkl")
    return model

model = train_or_load_model()

# Packet callback function for sniffing network traffic
def packet_callback(packet):
    try:
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
            current_time = datetime.now()
            if src_ip not in rate_limit_dict:
                rate_limit_dict[src_ip] = {'count': 0, 'first_seen': current_time}

            rate_limit_info = rate_limit_dict[src_ip]
            time_difference = (current_time - rate_limit_info['first_seen']).total_seconds()

            if time_difference > 60:  # Reset counter every 60 seconds
                rate_limit_info['count'] = 1
                rate_limit_info['first_seen'] = current_time
            else:
                rate_limit_info['count'] += 1

            if rate_limit_info['count'] > RATE_LIMIT_THRESHOLD:
                logging.warning(f"Rate limit exceeded for IP: {src_ip}")
                # Implement IP blocking logic
                ip_block_list.add(src_ip)
                block_ip(src_ip)  # Placeholder for actual IP blocking logic

            rate_limit_dict[src_ip] = rate_limit_info

    except Exception as e:
        logging.error(f"Error processing packet: {e}")

# Modified block_ip function to log blocked traffic
def block_ip(ip):
    global blocked_traffic_data
    # Placeholder: Implement actual IP blocking logic here
    logging.info(f"Blocking IP: {ip}")
    # Example: Update firewall rules, etc.

    # Log blocked traffic data
    blocked_traffic_data.append({
        'timestamp': datetime.now(),
        'src_ip': ip,
        'action': 'block'
    })

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

# Function to detect anomalies using machine learning
def detect_anomalies_with_ml():
    df = create_dataframe(traffic_data)
    if df.empty or 'packet_length' not in df.columns:
        return []

    # Label encoding for src_ip
    df['src_ip_encoded'] = LabelEncoder().fit_transform(df['src_ip'])
    df['packet_rate'] = df['packet_length'].rolling(window=5).mean().fillna(df['packet_length'])

    features = df[['packet_length', 'src_ip_encoded', 'packet_rate']].values
    predictions = model.predict(features)
    anomaly_indices = np.where(predictions == -1)[0]
    anomalous_data = df.iloc[anomaly_indices]
    return anomalous_data['src_ip'].unique().tolist()

# Function to get top 10 source IPs by traffic load
def get_top_source_ips():
    df = create_dataframe(traffic_data)
    if df.empty or 'src_ip' not in df.columns:
        return [], []

    traffic_summary = df.groupby('src_ip').size().nlargest(10)  # Get top 10 IPs
    top_ips = traffic_summary.index.tolist()
    top_ips_load = traffic_summary.tolist()
    return top_ips, top_ips_load

# Function to mitigate detected threats
def mitigate_threats(suspicious_ips, suspicious_profiles, surge_endpoints):
    for ip in suspicious_ips:
        if ip not in ip_block_list:
            ip_block_list.add(ip)
            logging.info(f"Blocking suspicious IP: {ip}")
            block_ip(ip)

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
            ml_anomalies = detect_anomalies_with_ml()

            # Mitigate threats
            mitigate_threats(suspicious_ips + ml_anomalies, suspicious_profiles, surge_endpoints)

            # Print or log the findings
            if suspicious_ips or suspicious_profiles or surge_endpoints or spike_patterns or ml_anomalies:
                logging.warning("Potential DDoS attack detected!")
                if suspicious_ips:
                    logging.info(f"Suspicious IPs: {suspicious_ips}")
                if ml_anomalies:
                    logging.info(f"ML Detected Anomalies: {ml_anomalies}")
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
                'bytes_recv': psutil.net_io_counters(pernic=True)[iface].bytes_recv,
                'packets_sent': psutil.net_io_counters(pernic=True)[iface].packets_sent,
                'packets_recv': psutil.net_io_counters(pernic=True)[iface].packets_recv
            }
    return stats

def get_thread_count():
    return psutil.Process().num_threads()



# Streamlit app function
def run_streamlit_app():
    # Set page configuration for wide layout
    st.set_page_config(layout="wide")

    # Display the main title at the top of the dashboard
    st.title("DDoS Protection System for Cloud")

    # Create placeholders for dynamic content
    traffic_chart_placeholder = st.empty()
    top_ips_chart_placeholder = st.empty()
    network_stats_placeholder = st.empty()
    ddos_status_placeholder = st.empty()
    blocked_traffic_placeholder = st.empty()
    attack_active_placeholder = st.empty()

    # Initialize protection_status
    protection_status = 100  # Default value

    # Protection Status in the sidebar
    with st.sidebar:
        st.header("Protection Status")
        # Linear Progress Bar
        st.markdown(f"""
            <div style="width: 100%; padding: 10px;">
                <div style="width: 100%; background-color: #e6e6e6; border-radius: 5px;">
                    <div style="width: {protection_status}%; background-color: skyblue; height: 30px; border-radius: 5px; text-align: center; color: white; line-height: 30px;">
                        {protection_status}%
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

        # DDoS Attack Summary Pie Chart
        st.header("DDoS Attack Summary")

        # Simulating attack data
        attack_summary = {
            'Suspicious IPs': len(detect_suspicious_traffic()),
            'Behavioral Floods': len(detect_behavioral_flood()),
            'Endpoint Surges': len(detect_endpoint_surge()),
            'ML Anomalies': len(detect_anomalies_with_ml()),
            'Odd Traffic Patterns': len(detect_odd_patterns())
        }

        # Creating a Pie Chart
        labels = list(attack_summary.keys())
        values = list(attack_summary.values())

        fig = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.4)])
        fig.update_layout(showlegend=True, legend=dict(x=-0.1, y=0.5, orientation="v"))
        fig.update_layout(title_text="DDoS Attack Summary", title_x=0.5)

        st.plotly_chart(fig)

        # Display thread status below the pie chart
        st.header("Thread Status")
        thread_count = get_thread_count()
        thread_status_percentage = min(thread_count, 100)  # Cap at 100% for display
        st.markdown(f"""
            <div style="width: 100%; padding: 10px;">
                <div style="width: 100%; background-color: #e6e6e6; border-radius: 5px;">
                    <div style="width: {thread_status_percentage}%; background-color: skyblue; height: 30px; border-radius: 5px; text-align: center; color: white; line-height: 30px;">
                        {thread_count} Threads
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

    while True:
        # Traffic Overview
        with traffic_chart_placeholder.container():
            st.header("Traffic Overview")
            df = create_dataframe(traffic_data)
            if not df.empty:
                st.line_chart(df['packet_length'], use_container_width=True)

        # Top 10 Source IPs
        with top_ips_chart_placeholder.container():
            st.header("Top 10 Source IPs")
            top_ips, top_ips_load = get_top_source_ips()
            if top_ips:
                st.bar_chart(data=dict(zip(top_ips, top_ips_load)), use_container_width=True)

        # Real-Time Network Stats with Bar Chart
        with network_stats_placeholder.container():
            st.header("Real-Time Network Stats")

            stats = get_network_stats()

            if stats:
                # Convert network stats to DataFrame for easy plotting
                stats_df = pd.DataFrame(stats).T  # Transpose to get interfaces as rows

                if stats_df.shape[1] == 4:  # Check if there are 4 columns
                    stats_df.columns = ['Bytes Sent', 'Bytes Received', 'Packets Sent', 'Packets Received']
                    stats_df.reset_index(inplace=True)
                    stats_df.columns = ['Interface', 'Bytes Sent', 'Bytes Received', 'Packets Sent', 'Packets Received']

                    fig = px.bar(
                        stats_df,
                        x='Interface',
                        y=['Bytes Sent', 'Bytes Received', 'Packets Sent', 'Packets Received'],
                        title="Real-Time Network Statistics",
                        labels={'value': 'Metrics', 'variable': 'Metric'},
                        barmode='group'
                    )
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.error("Unexpected structure of network statistics data.")

        # DDoS Detection Status
        with ddos_status_placeholder.container():
            st.header("DDoS Detection Status")
            suspicious_ips = detect_suspicious_traffic()
            suspicious_profiles = detect_behavioral_flood()
            surge_endpoints = detect_endpoint_surge()
            ml_anomalies = detect_anomalies_with_ml()

            if suspicious_ips or suspicious_profiles or surge_endpoints or ml_anomalies:
                st.warning("Potential DDoS attack detected!")
                if suspicious_ips:
                    st.info(f"Suspicious IPs: {suspicious_ips}")
                if ml_anomalies:
                    st.info(f"ML Detected Anomalies: {ml_anomalies}")
                if suspicious_profiles:
                    st.info(f"Suspicious Behavioral Profiles: {suspicious_profiles}")
                if surge_endpoints:
                    st.info(f"Surging Endpoints: {surge_endpoints}")
            else:
                st.success("No DDoS threats detected.")

        # Blocked Traffic Overview
        with blocked_traffic_placeholder.container():
            st.header("Blocked Traffic Overview")
            df_blocked = create_dataframe(blocked_traffic_data)
            if not df_blocked.empty:
                # Resample data by hour and count the blocked events
                df_blocked_resampled = df_blocked.resample('h').size().to_frame(name='blocked_count')
                if not df_blocked_resampled.empty:
                    st.line_chart(df_blocked_resampled, use_container_width=True)
                else:
                    st.info("No blocked traffic data to display.")
            else:
                st.info("No blocked traffic data available.")

        # Attack Active in Last 24 Hours
        with attack_active_placeholder.container():
            st.header("Attack Active in Last 24 Hours")
            df_attack = create_dataframe(blocked_traffic_data)
            if not df_attack.empty:
                df_attack_24h = df_attack[df_attack.index > (datetime.now() - pd.DateOffset(hours=24))]
                if not df_attack_24h.empty:
                    # Display the relevant information
                    st.write(df_attack_24h[['src_ip', 'action']])
                else:
                    st.info("No attack activity detected in the last 24 hours.")
            else:
                st.info("No attack data available.")

        # Wait for 3 seconds before updating the rest of the dashboard
        time.sleep(3)


if __name__ == '__main__':
    interface = 'en0'  # Replace with your network interface

    sniff_thread = threading.Thread(target=start_sniffing, args=(interface,))
    sniff_thread.start()

    analyze_thread = threading.Thread(target=analyze_traffic)
    analyze_thread.start()

    # Start the Streamlit app with the specified port
    subprocess.Popen(["streamlit", "run", "tool.py", "--server.port", "8332"])

    run_streamlit_app()
