# This file will analyze every .pcap file in pcap_file/ and generate a report
# for each one inside Better_Outputs/.

import os

from pcap_parser import build_packet_records


def write_basic_report(records, report_file):
    with open(report_file, "w") as file:
        for record in records:
            file.write(
                f"Source IP: {record['src_ip']}, "
                f"Destination IP: {record['dst_ip']}, "
                f"Protocol: {record['protocol']}\n"
            )

def main(pcap_file, report_file):
    records = build_packet_records(pcap_file)
    write_basic_report(records, report_file)

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
