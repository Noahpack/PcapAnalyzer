import openai
from dotenv import load_dotenv
import os
import time

from pcap_parser import build_packet_records, summarize_records, format_record_line

# Load environment variables from .env
load_dotenv()

# API Key check with more informative error message
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY environment variable not set.  Please create a .env file and add it.")

client = openai.OpenAI(api_key=api_key)

# Limits chosen to comfortably fit gpt-4's 8192-token context window and a
# 10,000 TPM rate limit tier (~4 chars/token). Packet data is parsed in full
# locally (free), then split into chunks for the rate-limited OpenAI calls.
CHUNK_CHAR_LIMIT = 4000
CHUNK_MAX_TOKENS = 300
SYNTHESIS_MAX_TOKENS = 800
MAX_SYNTHESIS_INPUT_CHARS = 4000
MAX_CHUNKS_PER_FILE = 20
INTER_CHUNK_SLEEP_SECONDS = 15
INTER_FILE_SLEEP_SECONDS = 10
MAX_RETRIES = 3


def truncate_text(text, max_chars):
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n... (truncated)"


def chunk_lines(lines, max_chars=CHUNK_CHAR_LIMIT):
    """Group formatted packet lines into text chunks, each capped at
    max_chars, so every OpenAI request stays within context/rate limits."""
    chunk = []
    chunk_len = 0
    for line in lines:
        line_len = len(line) + 1
        if chunk and chunk_len + line_len > max_chars:
            yield "\n".join(chunk)
            chunk = []
            chunk_len = 0
        chunk.append(line)
        chunk_len += line_len
    if chunk:
        yield "\n".join(chunk)


def call_chat_completion(messages, max_tokens, max_retries=MAX_RETRIES):
    """Shared OpenAI call with retry/backoff on rate limits, used by both the
    per-chunk insight calls and the final synthesis call."""
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model="gpt-4",  # Use "gpt-3.5-turbo" if GPT-4 is unavailable
                messages=messages,
                max_tokens=max_tokens,
                temperature=0.2 # Lower temperature for more deterministic and factual responses
            )
            return response.choices[0].message.content.strip()
        except openai.RateLimitError:
            wait_time = 15 * (attempt + 1)
            print(f"Rate limited by OpenAI API. Waiting {wait_time}s before retry ({attempt + 1}/{max_retries})...")
            time.sleep(wait_time)
        except Exception as e:  # Catch any other exception
            print(f"Error communicating with OpenAI API: {e}")  # Print the error for debugging
            return None
    print("Exceeded max retries due to rate limiting. Skipping this request.")
    return None


def generate_chunk_insight(chunk_text, label):
    messages = [
        {"role": "system", "content": (
            "You are a cybersecurity analyst reviewing a segment of network traffic "
            "extracted from a packet capture. Identify anomalies, suspicious patterns, "
            "and potential attacks (e.g. SQL injection, credential exposure, unusual "
            "hosts or requests). Be concise and specific, referencing IPs/hosts/timestamps "
            "where relevant. Respond in under 150 words as short bullet points."
        )},
        {"role": "user", "content": f"{label}:\n{chunk_text}"},
    ]
    return call_chat_completion(messages, max_tokens=CHUNK_MAX_TOKENS)


def generate_synthesis(filename, overview, chunk_insights):
    overview_lines = [
        f"Total packets analyzed: {overview['total_packets']}",
        f"Unique source IPs: {', '.join(overview['unique_src_ips']) or 'none'}",
        f"Unique destination IPs: {', '.join(overview['unique_dst_ips']) or 'none'}",
        f"Protocol breakdown: {overview['protocol_counts']}",
        f"HTTP requests detected: {overview['http_request_count']}",
        f"Suspicious findings (SQLi/credentials): {overview['suspicious_count']}",
    ]

    insight_text = "\n\n".join(f"{label}:\n{text}" for label, text in chunk_insights if text)
    insight_text = truncate_text(insight_text, MAX_SYNTHESIS_INPUT_CHARS) if insight_text else "None available."

    messages = [
        {"role": "system", "content": (
            "You are a senior network security analyst producing an executive summary "
            "for a pcap analysis report. Base your summary strictly on the provided "
            "statistics and preliminary findings; do not invent details not present in "
            "them. Structure your answer with an 'Executive Summary' paragraph followed "
            "by a 'Recommendations' bullet list."
        )},
        {"role": "user", "content": (
            f"Report for capture file: {filename}\n\n"
            "Overview statistics:\n" + "\n".join(overview_lines) +
            f"\n\nPreliminary findings from packet analysis:\n{insight_text}"
        )},
    ]
    return call_chat_completion(messages, max_tokens=SYNTHESIS_MAX_TOKENS)


def build_report(filename, overview, chunk_insights, synthesis_text, records, truncated_chunks):
    lines = []
    lines.append("=" * 70)
    lines.append(f"PCAP ANALYSIS REPORT: {filename}")
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)
    lines.append("")

    lines.append("OVERVIEW")
    lines.append(f"- Total packets analyzed: {overview['total_packets']}")
    lines.append(f"- Unique source IPs: {', '.join(overview['unique_src_ips']) or 'none'}")
    lines.append(f"- Unique destination IPs: {', '.join(overview['unique_dst_ips']) or 'none'}")
    lines.append(f"- Protocol breakdown: {overview['protocol_counts']}")
    lines.append(f"- HTTP requests detected: {overview['http_request_count']}")
    lines.append(f"- Suspicious findings (SQLi/credentials): {overview['suspicious_count']}")
    lines.append("")

    lines.append("EXECUTIVE SUMMARY (AI-Generated)")
    lines.append(synthesis_text or "Unavailable due to an OpenAI API error.")
    lines.append("")

    lines.append("DETAILED FINDINGS (AI-Generated, per packet-range chunk)")
    if chunk_insights:
        for label, text in chunk_insights:
            lines.append(f"[{label}]")
            lines.append(text or "Unavailable due to an OpenAI API error.")
            lines.append("")
    else:
        lines.append("No packets available to analyze.")
        lines.append("")

    if truncated_chunks:
        lines.append(
            f"NOTE: {truncated_chunks} additional packet chunk(s) were not sent to OpenAI "
            "to stay within rate limits; see Packet-Level Data below for full detail."
        )
        lines.append("")

    lines.append("PACKET-LEVEL DATA")
    if records:
        for record in records:
            lines.append(format_record_line(record))
    else:
        lines.append("No IP packets found in capture.")
    lines.append("")

    return "\n".join(lines)


def process_pcap_file(pcap_path, output_path, filename):
    records = build_packet_records(pcap_path)
    overview = summarize_records(records)
    lines = [format_record_line(record) for record in records]
    chunks = list(chunk_lines(lines))

    chunks_to_send = chunks[:MAX_CHUNKS_PER_FILE]
    truncated_chunks = len(chunks) - len(chunks_to_send)

    chunk_insights = []
    for i, chunk_text in enumerate(chunks_to_send, start=1):
        label = f"Packets chunk {i}/{len(chunks)}"
        print(f"Analyzing {label} for {filename}...")
        insight = generate_chunk_insight(chunk_text, label)
        chunk_insights.append((label, insight))
        if i < len(chunks_to_send):
            time.sleep(INTER_CHUNK_SLEEP_SECONDS)

    synthesis_text = generate_synthesis(filename, overview, chunk_insights)

    report = build_report(filename, overview, chunk_insights, synthesis_text, records, truncated_chunks)

    with open(output_path, "w", encoding="utf-8") as file:
        file.write(report)


def process_folder(input_folder, output_folder):
    pcap_files = [f for f in os.listdir(input_folder) if f.lower().endswith(".pcap")]

    for index, input_file in enumerate(pcap_files):
        input_file_path = os.path.join(input_folder, input_file)
        output_file_path = os.path.join(output_folder, input_file + ".txt") # Add .txt extension

        try:
            process_pcap_file(input_file_path, output_file_path, input_file)
        except Exception as e:  # Catch and report file processing errors
            print(f"Error processing file {input_file}: {e}")

        # Space out requests so consecutive files don't stack up against the
        # per-minute token rate limit.
        if index < len(pcap_files) - 1:
            time.sleep(INTER_FILE_SLEEP_SECONDS)


# Input and output folder paths
input_folder_path = "./pcap_file"  # Or wherever your pcap files are
output_folder_path = "./Better_Outputs" # Your output path

# Ensure output folder exists
os.makedirs(output_folder_path, exist_ok=True)

# Process the folder and generate explanations
process_folder(input_folder_path, output_folder_path)

print("Reports generated and saved to Better_Outputs folder.")
