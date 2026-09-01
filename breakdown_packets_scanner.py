# This code will analyze the first 20 packets of every .pcap file in
# pcap_file/ and generate a detailed HTTP breakdown report for each one
# inside Better_Outputs/.

import os

from pcap_parser import build_packet_records

PACKET_LIMIT = 20


def write_http_breakdown(records, report_file):
    with open(report_file, "w") as file:
        for record in records:
            if record["index"] > PACKET_LIMIT:
                break
            if not record["request_type"]:
                continue

            line = (
                f"{record['timestamp']} - Source IP: {record['src_ip']}, "
                f"Destination IP: {record['dst_ip']} - "
                f"Protocol: {record['protocol']}, Type: {record['request_type']}, "
                f"URL: {record['url']} "
            )
            if record["credentials_found"]:
                line += f"Credentials: {record['credentials_hint']} "
            if record["status_code"]:
                line += f"Status: {record['status_code']} "
            if record["host"]:
                line += f"Host: {record['host']} "
            if record["user_agent"]:
                line += f"User-Agent: {record['user_agent']} "
            if record["accept"]:
                line += f"Accept: {record['accept']} "
            if record["referer"]:
                line += f"Referer: {record['referer']} "
            if record["cookies_present"]:
                line += "Cookies present "
            if record["multipart_form_data"]:
                line += "MIME Multipart Media Encapsulation Detected "
            if record["sql_injection_suspected"]:
                line += "Potential SQL Injection Attack Detected "

            file.write(line.strip() + "\n")

def main(pcap_file, report_file):
    records = build_packet_records(pcap_file)
    write_http_breakdown(records, report_file)

def process_folder(input_folder, output_folder):
    os.makedirs(output_folder, exist_ok=True)
    pcap_files = [f for f in os.listdir(input_folder) if f.lower().endswith(".pcap")]

    for pcap_file in pcap_files:
        input_path = os.path.join(input_folder, pcap_file)
        output_path = os.path.join(output_folder, pcap_file + ".txt")
        main(input_path, output_path)
        print(f"Analysis completed for {pcap_file}. Report saved to {output_path}")

if __name__ == "__main__":
    input_folder_path = "./pcap_file"
    output_folder_path = "./Better_Outputs"

    process_folder(input_folder_path, output_folder_path)
