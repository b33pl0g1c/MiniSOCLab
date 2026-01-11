# MiniSOCLab: AI-Powered Security Operations Center


'''                                                                                                                 
 _      _  _      _  ____  ____  ____    _     ____  ____ 
/ \__/|/ \/ \  /|/ \/ ___\/  _ \/   _\  / \   /  _ \/  _ \
| |\/||| || |\ ||| ||    \| / \||  /    | |   | / \|| | //
| |  ||| || | \||| |\___ || \_/||  \__  | |_/\| |-||| |_\\
\_/  \|\_/\_/  \|\_/\____/\____/\____/  \____/\_/ \|\____/
                                                                                                                                                                                                '''            
                                                                                
                                                                                

A specialized Mini SOC environment that leverages **Wazuh SIEM** for threat detection and **Infrastructure as Code (Terraform)** for deployment. This project integrates with **Claude Desktop** via the Model Context Protocol (MCP), allowing an LLM to perform intelligent threat analysis on live security logs.

##  Architecture Flow

The system operates in three layers:

1.  **Infrastructure Layer (Terraform & AWS):**
    * Automatically provisions three AWS EC2 instances:
        * **Wazuh Indexer** (`t3.xlarge`): Stores log data.
        * **Wazuh Server** (`t3.medium`): Processes data and triggers rules.
        * **Wazuh Dashboard** (`t3.large`): Web UI for visualization.
    * Security groups are configured to allow necessary traffic (Ports 55000, 443, 1514, etc.).

2.  **Detection Layer (Wazuh & Custom Rules):**
    * The SIEM is pre-loaded with custom detection rules for:
        * **Sysmon:** Mapped to MITRE ATT&CK techniques (Process Injection, Credential Dumping).
        * **Mikrotik:** Router security events (IPsec errors, login anomalies).
        * **WPScan:** WordPress vulnerability scanning logs.

3.  **Intelligence Layer (MCP & LLM):**
    * An **MCP Server** (`wazuh_mcp_server.py`) acts as a bridge between the Wazuh API and Claude.
    * **Claude Desktop** connects to this server to fetch summaries, drill down into alert details, and provide human-readable threat analysis.

---

##  Prerequisites

* **AWS Account** with valid credentials configured locally.
* **Terraform** installed.
* **Python 3.10+** installed.
* **Claude Desktop** application.

---

##  Setup Instructions

### Phase 1: Deploy Infrastructure

1.  Navigate to the Terraform directory:
    ```bash
    cd terraform_files
    ```
2.  Initialize Terraform:
    ```bash
    terraform init
    ```
3.  Deploy the instances:
    ```bash
    terraform apply --auto-approve
    ```
4.  Once finished, note the **Public IP** of the `wazuh_server_13700` from the output.

### Phase 2: Configure the MCP Server

1.  Install the required Python libraries:
    ```bash
    pip install -r requirements.txt
    ```
2.  Open `wazuh_mcp_server.py` (or set environment variables) and update the configuration with your Wazuh Server IP and credentials:
    ```python
    WAZUH_API_URL = "https://<YOUR_WAZUH_SERVER_PUBLIC_IP>:55000"
    WAZUH_USER = "wazuh-wui"
    WAZUH_PASSWORD = "<YOUR_WAZUH_PASSWORD>"
    ```

### Phase 3: Connect Claude Desktop

1.  Locate or create your Claude Desktop configuration file:
    * **Mac:** `~/Library/Application Support/Claude/claude_desktop_config.json`
    * **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
2.  Add the Wazuh MCP server to the configuration:
    ```json
    {
      "mcpServers": {
        "wazuh-analyst": {
          "command": "python",
          "args": ["/absolute/path/to/your/repo/wazuh_mcp_server.py"],
          "env": {
            "WAZUH_API_URL": "https://<YOUR_WAZUH_IP>:55000",
            "WAZUH_USER": "wazuh-wui",
            "WAZUH_PASSWORD": "wazuh"
          }
        }
      }
    }
    ```
3.  Restart Claude Desktop.

---

## 🧠 How to Use

Once connected, you can ask Claude questions like:

> "Check the recent threat summary. Are there any critical alerts related to credential dumping?"

> "I see a suspicious Sysmon event in the summary. Get the full details for alert ID '12345' and analyze the process command line for malicious flags."

---

##  Repository Structure

* `terraform_files/`: Terraform scripts for AWS deployment.
* `custom_rules/`: XML rule definitions for Sysmon, Mikrotik, and WPScan.
* `wazuh_mcp_server.py`: The Python bridge for the Model Context Protocol.
* `requirements.txt`: Python dependencies.
