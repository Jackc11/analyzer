import os
import json
import urllib.request
from datetime import datetime

SERVER_URL = "http://localhost:8080"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILENAME = f"download_{TIMESTAMP}.pcap"
CONFIG = {
    "ip": "127.0.0.1",
    "port": 1516,
    "device_name": "Intel(R) Ethernet Controller (3) I225-V",
    "pcap_name": "traffic.pcap",
    "snaplen": 65536,
    "is_loop_back": False,
    "filter": {
        "address": [
            "192.168.1.3"
        ],
        "port": [
            "3030"
        ]
    }
}

def download_pcap(url, output_path) -> None:
    print(f"Connecting to {url}")
    try:
        with urllib.request.urlopen(url) as response:
            if response.status == 204:
                print("No pcaps")
                return
            elif response.status != 200:
                print(f"Server response with status: {response.status}")
                return

            print(f"Download started. Safed as '{output_path}'...")

            with open(output_path, "wb") as f:
                f.write(response.read())
                
        print(f"Successfully downloaded pcap. Size: {os.path.getsize(output_path)} bytes")

    except urllib.error.URLError as e:
        print(f"Failed to connect to analyzer")
        print(f"Reason: {e.reason}")
    except Exception as e:
        print(f"Failed to connect: {e}")

def send_config(url: str) -> None:
    conf = json.dumps(CONFIG).encode('utf-8')

    print(f'Send the config ${conf}\n')
    req = urllib.request.Request(url, data=conf, method='POST')
    req.add_header('Content-Type', 'application/json')    

    try:
        with urllib.request.urlopen(url) as res:
            print(f"Server response with status: {res.status}")
            print(res.read().decode('utf-8'))
    except Exception as e:
        print(f"Failed to send config {e}")

def main() -> None:
    while True:
        print('Enter command\n1 - Send config to analyzer\n' \
        '2 - Start to capture traffic\n' \
        '3 - Stop to capture traffic\n' \
        '4 - Download pcap\n' \
        '99 - Close remote')
        cmd = input('> ')

        if cmd == '99':
            break

        if cmd == '1':
            send_config(SERVER_URL + '/config')
        elif cmd == '4':
            download_pcap(SERVER_URL + '/pcap', OUTPUT_FILENAME)            

if __name__ == "__main__":
    main()
