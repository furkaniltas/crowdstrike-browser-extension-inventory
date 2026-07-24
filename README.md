# CrowdStrike Browser Extension Inventory

Inventory Chrome, Microsoft Edge and Firefox extensions across Windows endpoints using **CrowdStrike Falcon RTR**, **Falcon API**, **PowerShell** and **Python**.

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

```
Python Script
      │
      │ Falcon API
      ▼
CrowdStrike Cloud
      │
      │ RTR
      ▼
Windows Endpoints
      │
      ▼
PowerShell Script
      │
      ▼
JSON Output
      │
      ▼
CSV Report
```

---

## Repository Structure

```
powershell/
    BrowserExtensionInventory.ps1

python/
    falcon_extension_inventory.py
```

---

## Requirements

- CrowdStrike Falcon
- RTR Admin permissions
- Python 3.8+
- Windows endpoints

---

## Output

The project generates:

- `extension_inventory.csv`
- `extension_inventory_failures.csv`

---

## License

MIT License
