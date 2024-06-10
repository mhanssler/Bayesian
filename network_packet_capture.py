import pyshark

def test_capture(interface, duration):
    capture = pyshark.LiveCapture(interface=interface)
    print("Starting capture...")
    capture.sniff(timeout=duration)
    print("Capture complete.")
    print(f"Number of packets captured: {len(capture)}")
    for packet in capture:
        print(packet)

if __name__ == "__main__":
    interface = "Wi-Fi"  # Replace with your WiFi network interface name
    duration = 10  # Duration in seconds
    test_capture(interface, duration)
