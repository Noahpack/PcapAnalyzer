# PcapAnalyzer
Welcome to PcapAnalyzer, a comprehensive toolkit for working with pcap files, which are commonly used to store network traffic captures. This repository provides a suite of tools designed to analyze, inspect, and extract insights from packet capture files. Whether you are a network security professional, a system administrator, or a developer working on network-related projects, PcapAnalyzer equips you with the essential utilities to streamline your pcap file analysis workflow.

Also, I added OpenAI's GPT-3 model to generate a report for the pcap file. The report is generated in the form of a text file. The report contains the following information:

- Source IP
- Destination IP
- Host: [URL, IP]
- Type of vulnerability: [if any]
- Description of the problem: [if any]
- Possible Solutions: [if any]
- User-Agent: [Browser, OS, Device]
- Request Type: [Get, Post, Put, Delete]
- Is Successful: [yes, no]

In this project, we are utilizing two different AI models for text generation and analysis. The setup is as follows:

## Main Branch: OpenAI

- On the main branch, the project uses OpenAI's API to generate responses, explanations, and solutions. This integration allows the system to process network intrusion detection data and generate detailed reports based on the AI's analysis.
- `pcap_formatted.py` on this branch imports `openai` and reads `OPENAI_API_KEY` from your `.env` file.

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
- PacketInspector: A tool for in-depth inspection of individual network packets.

- FilterUtility: Efficiently filter and sort pcap files based on specific criteria.

- ExtractionWizard: Extract files, data, or metadata from pcap captures.

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

## Step 6: Folders and paths you need to change
These folders/files are project-specific and must be updated to match your own machine before running anything:
- `pcap_file/` — Put your own `.pcap` capture file(s) here. This is the input folder read by `pcap_scanner.py`, `breakdown_packets_scanner.py`, and `pcap_formatted.py`.
- `Better_Outputs/` — This is where `pcap_formatted.py` writes its AI-generated reports. It's created automatically if missing, but you should still confirm the path.
- `Examples_Outputs/` — Sample output for reference only; not required to run the tools.
- Inside the code, update these hardcoded values to match your setup:
  - `pcap_scanner.py` and `breakdown_packets_scanner.py`: update `pcap_file_path` (defaults to `./pcap_file/IT6300FE.pcap`) and `report_file_path` to point at your own capture file and desired report name.
  - `pcap_formatted.py`: update `input_folder_path` and `output_folder_path` — these currently point at an absolute path (e.g. `/Users/alanharo/Documents/GitHub/PcapAnalyzer/...`) that only works on the original author's machine. Change them to your own repo location, or to relative paths like `"./pcap_file"` and `"./Better_Outputs"`.
  - If your pcap file is large, you can change how many packets are analyzed by editing the slice in the packet loop, e.g.:
    ```
    for packet in packets[:20]:
            analyze_http_packet(packet, report_file)
    ```

## Step 7: Run the tools
```
python pcap_scanner.py             # basic IP/protocol report
python breakdown_packets_scanner.py  # detailed HTTP request report
python pcap_formatted.py           # AI-generated report (needs your .env API key set up above)
```

# Contributing:
Contributions to PcapAnalyzer are welcome! Feel free to submit bug reports, feature requests, or even pull requests to enhance the functionality of this pcap analysis toolkit.

