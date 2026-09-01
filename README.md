# PcapAnalyzer
Welcome to PcapAnalyzer, a comprehensive toolkit for working with pcap files, which are commonly used to store network traffic captures. This repository provides a suite of tools designed to analyze, inspect, and extract insights from packet capture files. Whether you are a network security professional, a system administrator, or a developer working on network-related projects, PcapAnalyzer equips you with the essential utilities to streamline your pcap file analysis workflow.

Also, I added an OpenAI-powered analysis pass (`pcap_formatted.py`) that generates one detailed, narrative report per `.pcap` file. Every packet is parsed locally, then grouped into chunks sent to GPT-4 for security analysis, and combined into a text-file report containing:

- **Overview**: total packets analyzed, unique source/destination IPs, protocol breakdown, HTTP request count, and suspicious-finding count — computed locally so the numbers are always accurate.
- **Executive Summary (AI-generated)**: a narrative summary and recommendations synthesized from all chunk-level findings.
- **Detailed Findings (AI-generated)**: per packet-range chunk, called-out anomalies, suspicious patterns, and potential attacks (e.g. SQL injection, exposed credentials, unusual hosts).
- **Packet-Level Data**: a full line-by-line record of every parsed packet (IPs, protocol, HTTP method/URL/host/status, headers, credential/SQLi flags), for reference alongside the AI narrative.

In this project, we are utilizing two different AI models for text generation and analysis. The setup is as follows:

## Main Branch: OpenAI

- On the main branch, the project uses OpenAI's API to generate responses, explanations, and solutions. This integration allows the system to process network intrusion detection data and generate detailed reports based on the AI's analysis.
- `pcap_formatted.py` on this branch imports `openai` and reads `OPENAI_API_KEY` from your `.env` file. It parses every packet via the shared `pcap_parser.py` module, then sends the data to GPT-4 in rate-limit-aware chunks (see Step 6 below for the tunable constants).

## Dev Branch: GEMINI (Google's Generative AI)

- In the dev branch, we are using GEMINI, a generative AI model from Google, to handle the same tasks. GEMINI is used for analyzing network packets and generating explanations or security solutions based on the packet data. The dev branch allows you to test and compare the performance and accuracy of GEMINI against OpenAI.
- `pcap_formatted.py` on this branch imports `google.generativeai` and reads `GEMINI_API_KEY` from your `.env` file.

> IMPORTANT: `main` and `dev` are NOT meant to be merged together. They are two parallel implementations of the same tool, one per AI provider. Check out whichever branch matches the AI provider you want to use (`git checkout main` for OpenAI, `git checkout dev` for Gemini) and stay on it.

## Key Features:
- Packet Inspection: Dive deep into network packets to examine headers, payloads, and other relevant information.

- Traffic Analysis: Gain insights into network traffic patterns, protocols, and potential anomalies.

- Filtering Capabilities: Efficiently filter and sort packets based on various criteria, enhancing targeted analysis.

- Extraction Tools: Extract specific data, files, or metadata from pcap files for further examination.

- Integration Support: Seamlessly integrate PcapAnalyzer into your existing network security or monitoring workflows.

- User-Friendly Interface: Enjoy a user-friendly interface that simplifies the complexities of pcap file analysis.

## Getting Started:
To get started, clone the repository and explore the documentation for detailed instructions on installing, configuring, and utilizing the tools provided by PcapAnalyzer.

## Tools Included:
- `pcap_parser.py`: Shared parsing module used by all three tools below — extracts per-packet IP/protocol, HTTP method/URL/host/status/headers, credential exposure, and SQL-injection indicators from a `.pcap` file.

- `pcap_scanner.py`: Basic, no-API-key scan — one `Source IP, Destination IP, Protocol` line per packet, unlimited packets.

- `breakdown_packets_scanner.py`: No-API-key detailed HTTP breakdown (method, URL, host, status, headers, credentials, SQLi flag) for the first 20 packets of each capture.

- `pcap_formatted.py`: AI-powered consolidated report combining the data above for every packet in the capture with GPT-4-generated insights (see report structure above). Requires an OpenAI API key.

# Step-by-Step Setup Guide
Follow these steps in order the first time you set up the project on your own machine.

## Step 1: Pick your branch (OpenAI vs. Gemini)
This repo has two long-lived branches that each hold a complete, independent implementation:
- `main` -> uses **OpenAI**. Check it out with `git checkout main`.
- `dev` -> uses **Gemini**. Check it out with `git checkout dev`.

Do not mix them: pick one provider, check out the matching branch, and do all your work there.

## Step 2: Clone the repository
```
git clone <repo-url>
cd PcapAnalyzer
git checkout main   # or: git checkout dev
```

## Step 3: Install dependencies
- Install Scapy (used on both branches to parse pcap files): `pip install scapy`
- Install `python-dotenv` (used on both branches to load your `.env` file): `pip install python-dotenv`
- On `main` (OpenAI), also install: `pip install openai`
- On `dev` (Gemini), also install: `pip install google-generativeai`

## Step 4: Get API access and credits
You only need to do the section for the provider matching the branch you checked out in Step 1.

### OpenAI (for the `main` branch)
1. Go to https://platform.openai.com/ and sign up or log in.
2. Open the [Billing page](https://platform.openai.com/settings/organization/billing/overview) in your account settings and add a payment method, then purchase credits (OpenAI's chat completion API, including the `gpt-4` model used in this repo, requires paid credits/a positive balance — free trial credit is no longer reliably available for new accounts).
3. Go to the [API Keys page](https://platform.openai.com/api-keys) and click **Create new secret key**.
4. Copy the generated key immediately and store it somewhere safe — OpenAI will not show it to you again.
5. Optionally set a usage limit/budget alert under Billing > Limits so you don't get an unexpectedly large bill.

### Gemini (for the `dev` branch)
1. Go to [Google AI Studio](https://aistudio.google.com/) and sign in with a Google account.
2. Click **Get API key** > **Create API key**, and either create a new Google Cloud project or attach it to an existing one.
3. Copy the generated key and store it somewhere safe.
4. Gemini API usage is free up to a generous quota on the free tier. If you need higher rate limits/quota, go to the [Google Cloud Console](https://console.cloud.google.com/), select your project, enable billing under **Billing**, and enable the **Generative Language API** under **APIs & Services**.

## Step 5: Create your `.env` file
In the root of the repo, create a file named `.env` (it is already listed in `.gitignore`, so it will never be committed). Add only the line that matches your branch:
```
# main branch (OpenAI)
OPENAI_API_KEY=your_openai_key_here

# dev branch (Gemini)
GEMINI_API_KEY=your_gemini_key_here
```

## Step 6: Folders and paths
No hardcoded paths need to be edited anymore — all three scripts loop over every `.pcap` file automatically:
- `pcap_file/` — Drop any number of your own `.pcap` capture files here. All three scripts (`pcap_scanner.py`, `breakdown_packets_scanner.py`, `pcap_formatted.py`) read every `.pcap` file in this folder automatically.
- `Better_Outputs/` — Each script writes one `<capture-name>.pcap.txt` report per input file here. It's created automatically if missing.
- `Examples_Outputs/` — Sample output for reference only; not required to run the tools.
- `breakdown_packets_scanner.py` only analyzes the first 20 packets of each capture (`PACKET_LIMIT` constant at the top of the file) — raise this if you need deeper coverage of a specific file, or use `pcap_scanner.py`/`pcap_formatted.py` for unlimited coverage.
- `pcap_formatted.py` has a few tunable constants at the top of the file to match your OpenAI rate-limit tier:
  - `CHUNK_CHAR_LIMIT` (default 4000) — how much packet data goes into each GPT-4 request.
  - `MAX_CHUNKS_PER_FILE` (default 20) — caps how many chunks per capture get sent to OpenAI (all packets still appear in the Packet-Level Data section regardless).
  - `INTER_CHUNK_SLEEP_SECONDS` / `INTER_FILE_SLEEP_SECONDS` (default 15/10) — pacing between API calls to stay under your tokens-per-minute limit. Lower these if you're on a higher tier.

## Step 7: Run the tools
```
python pcap_scanner.py               # basic IP/protocol report, one file per capture in pcap_file/
python breakdown_packets_scanner.py  # detailed HTTP breakdown, first 20 packets of each capture
python pcap_formatted.py             # AI-generated narrative report (needs your .env API key set up above)
```
`pcap_formatted.py` makes real, billed OpenAI API calls and paces requests (see Step 6) to respect rate limits, so it can take several minutes per capture for larger files — this is expected, not a hang.

# Contributing:
Contributions to PcapAnalyzer are welcome! Feel free to submit bug reports, feature requests, or even pull requests to enhance the functionality of this pcap analysis toolkit.

