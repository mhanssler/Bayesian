import pyshark
import logging
import sys
from datetime import datetime
import time

def configure_logging():
    logger = logging.getLogger("NetworkMonitor")
    logger.setLevel(logging.DEBUG)
    
    # Create console handler for streaming
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(logging.DEBUG)
    
    # Create file handler with yyyymmdd format
    log_filename = datetime.now().strftime('%Y%m%d') + '.log'
    file_handler = logging.FileHandler(log_filename)
    file_handler.setLevel(logging.DEBUG)
    
    # Create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    stream_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)
    
    # Add the handlers to the logger
    logger.addHandler(stream_handler)
    logger.addHandler(file_handler)
    
    return logger

def extract_domains_from_packet(packet):
    domains = set()
    try:
        if 'http' in packet:
            domains.add(packet.http.host)
        if 'ssl' in packet and hasattr(packet.ssl, 'handshake_extensions_server_name'):
            domains.add(packet.ssl.handshake_extensions_server_name)
    except AttributeError:
        pass
    return domains

def monitor_network(interface, duration, logger):
    capture = pyshark.LiveCapture(interface=interface)
    unique_domains = set()

    logger.info("Monitoring network traffic...")
    start_time = time.time()
    
    for packet in capture.sniff_continuously():
        if time.time() - start_time > duration:
            break
        domains = extract_domains_from_packet(packet)
        if domains:
            new_domains = domains - unique_domains
            if new_domains:
                unique_domains.update(new_domains)
                for domain in new_domains:
                    logger.info(f"New domain detected: {domain}")

    return unique_domains

if __name__ == "__main__":
    logger = configure_logging()
    interface = "wlan0"  # Replace with your WiFi network interface
    duration = 60  # Duration in seconds (e.g., 60 seconds)
    unique_domains = monitor_network(interface, duration, logger)
    logger.info("Unique domains monitored:")
    for domain in unique_domains:
        logger.info(domain)
