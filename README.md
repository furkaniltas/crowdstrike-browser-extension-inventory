![Python](https://img.shields.io/badge/Python-3.8+-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-5391FE)
![License](https://img.shields.io/badge/License-MIT-green)

# CrowdStrike Browser Extension Inventory

Inventory Google Chrome, Microsoft Edge and Mozilla Firefox extensions across Windows endpoints using **CrowdStrike Falcon RTR**, **Falcon API**, **PowerShell**, and **Python**.

This project executes a PowerShell script across an entire CrowdStrike Host Group using Real Time Response (RTR), collects JSON results from each endpoint, and generates consolidated CSV reports for browser extension inventory.

## Features

- Inventory Chrome, Edge and Firefox extensions
- Supports all local user profiles
- Resolves localized extension names
- Supports Firefox `.xpi` packages
- Excludes Firefox themes
- Generates a consolidated CSV report
- Reports offline and failed hosts separately
- Designed for CrowdStrike Falcon Real Time Response (RTR)

---

## Architecture

```text
Python Controller
        │
        ▼
Authenticate to Falcon API
        │
        ▼
Create RTR Session
        │
        ▼
Execute PowerShell Script
        │
        ▼
Collect JSON Results
        │
        ▼
Generate CSV Reports

```

---

## Repository Structure

```

├── powershell/
│   └── BrowserExtensionInventory.ps1
├── python/
│   └── falcon_extension_inventory.py
├── LICENSE
└── README.md

```

---

## Quick Start

1. Upload `BrowserExtensionInventory.ps1` to **CrowdStrike Falcon → Response Scripts and Files**.
2. Create a Falcon API Client with the required RTR Admin permissions.
3. Set your Falcon API credentials as environment variables.
4. Execute the Python controller.

```powershell
$env:FALCON_CLIENT_ID="YOUR_CLIENT_ID"
$env:FALCON_CLIENT_SECRET="YOUR_CLIENT_SECRET"
$env:FALCON_BASE_URL="https://api.eu-1.crowdstrike.com"

python falcon_extension_inventory.py `
    --host-group-id "HOST_GROUP_ID" `
    --script-name "BrowserExtensionInventory"
```

## Requirements

- CrowdStrike Falcon
- RTR Admin permissions
- Python 3.8+
- Windows endpoints

---
## Required API Scopes

The Falcon API Client requires the following permissions:

| Scope              | Permission |
|--------------------|------------|
| Hosts              | Read       |
| Real Time Response | Read       |
| Real Time Response | Write      |
| Scripts            | Read       |

> **Note:** Administrator-level RTR permissions may be required depending on your Falcon policy configuration.

## Sample Output

### extension_inventory.csv

| ComputerName | Browser | Extension           | Version  | Enabled |
|--------------|---------|---------------------|----------|---------|
| PC-001       | Chrome  | Bitwarden           | 2025.7.0 | Yes     |
| PC-001       | Edge    | Microsoft Editor    | 1.2.3    | Yes     |
| PC-002       | Firefox | uBlock Origin       | 1.65.0   | Yes     |
| PC-003       | Chrome  | Google Docs Offline | 1.89     | No      |

## Output

The project generates the following reports:

- `extension_inventory.csv` — Successfully collected browser extension inventory.
- `extension_inventory_failures.csv` — Hosts that were offline or returned errors during execution.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Trademark Notice

This project is an independent community project created for educational and administrative purposes. It is not affiliated with, endorsed by, or sponsored by CrowdStrike.
