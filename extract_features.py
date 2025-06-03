from scapy.all import PcapReader
import pandas as pd
from datetime import datetime

def generate_flow_dataset(pcap_path, output_csv=None):
    if output_csv is None:
        output_csv = "flows.csv"

    flows = []
    current_flows = {}

    with PcapReader(pcap_path) as pcap_reader:
        for pkt in pcap_reader:
            if 'IP' not in pkt:
                continue

            try:
                src = pkt[0][1].src
                dst = pkt[0][1].dst
                proto = pkt[0][1].proto
                timestamp = pkt.time
                pkt_len = len(pkt)

                key = (src, dst, proto)
                if key not in current_flows:
                    current_flows[key] = {
                        'start_time': timestamp,
                        'packet_count': 0,
                        'byte_count': 0
                    }

                flow = current_flows[key]
                flow['packet_count'] += 1
                flow['byte_count'] += pkt_len
                flow['end_time'] = timestamp

            except Exception as e:
                continue  # Skip malformed packets

        for key, flow in current_flows.items():
            duration = flow['end_time'] - flow['start_time']
            flows.append({
                'src': key[0],
                'dst': key[1],
                'proto': key[2],
                'duration': duration,
                'packet_count': flow['packet_count'],
                'byte_count': flow['byte_count'],
                'bytes_per_sec': flow['byte_count'] / duration if duration > 0 else float('inf')
            })

    df = pd.DataFrame(flows)
    df.to_csv(output_csv, index=False)
    print(f"[+] Saved {len(df)} network flows to `{output_csv}`")
    return df