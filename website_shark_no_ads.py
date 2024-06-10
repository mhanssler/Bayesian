import pyshark
import logging
import sys
from datetime import datetime
import time

class MonitorConfig:
    def __init__(self, interface, duration, source_ip=None):
        self.interface = interface
        self.duration = duration
        self.source_ip = source_ip

def configure_logging():
    logger = logging.getLogger("NetworkMonitor")
    logger.setLevel(logging.INFO)
    
    # Create console handler for streaming
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.INFO)
    
    # Create file handler with yyyymmdd format
    log_filename = datetime.now().strftime('%Y%m%d') + '.log'
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.INFO)
    
    # Create a logging format
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    # Add the handlers to the logger
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    
    return logger

def extract_http_info(packet, logger):
    if hasattr(packet, 'http'):
        if hasattr(packet.http, 'host'):
            host = packet.http.host
            uri = packet.http.request_full_uri if hasattr(packet.http, 'request_full_uri') else packet.http.request_uri
            method = packet.http.request_method if hasattr(packet.http, 'request_method') else 'UNKNOWN'
            logger.info(f"HTTP {method} request to {host}{uri}")
        if hasattr(packet.http, 'response_code'):
            response_code = packet.http.response_code
            logger.info(f"HTTP response from {packet.http.host} with status code: {response_code}")

def extract_tls_info(packet, logger):
    if hasattr(packet, 'tls'):
        if hasattr(packet.tls, 'handshake_extensions_server_name'):
            sni = packet.tls.handshake_extensions_server_name
            logger.info(f"TLS handshake with SNI: {sni}")
        if hasattr(packet.tls, 'record_version'):
            tls_version = packet.tls.record_version
            logger.info(f"TLS version: {tls_version}")

def monitor_network(config, logger):
    if config.source_ip:
        capture_filter = f'ip.src == {config.source_ip} and (http or tls.handshake.type == 1)'
    else:
        capture_filter = 'http or tls.handshake.type == 1'
        
    capture = pyshark.LiveCapture(interface=config.interface, display_filter=capture_filter)
    unique_domains = set()

    logger.info("Monitoring network traffic...")
    start_time = time.time()
    
    for packet in capture.sniff_continuously():
        if time.time() - start_time > config.duration:
            break
        extract_http_info(packet, logger)
        extract_tls_info(packet, logger)

    logger.info("Monitoring completed.")

if __name__ == "__main__":
    logger = configure_logging()
    interface = "Wi-Fi"  # Replace with your WiFi network interface name
    duration = 600  # Duration in seconds (e.g., 60 seconds)
    source_ip = None  # Set to your device's IP address if needed, or leave as None
    config = MonitorConfig(interface, duration, source_ip)
    monitor_network(config, logger)
