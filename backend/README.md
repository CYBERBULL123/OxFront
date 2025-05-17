# OxSecure Suite

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)](LICENSE)

A comprehensive security toolkit that combines artificial intelligence with cybersecurity tools to provide intelligent threat detection, analysis, and response capabilities.

## 🔒 Overview

OxSecure Suite is an advanced security platform powered by Google's Gemini AI, offering a comprehensive set of tools for security professionals, analysts, and developers. The suite consists of three powerful modules:

- **🔍 OxInteLL**: Security intelligence gathering for domains, files, and code analysis with agentic workflow
- **📄 OxRAG**: Retrieval-Augmented Generation for context-aware document analysis
- **🖼️ OxImage**: AI-powered image generation and analysis for security visualization

## ⚙️ Key Features

- **Domain Intelligence**: Complete analysis with WHOIS, DNS records, port scanning, and vulnerability detection
- **File Security**: Hash calculation, malware detection, and AI-powered threat assessment
- **CVE Tracking**: Monitor and analyze security vulnerabilities with detailed explanations
- **Document Analysis**: Intelligent analysis of PDFs, websites, and text content
- **AI Image Generation**: Create security-focused visualizations and diagrams
- **Secure Authentication**: JWT-based authentication system with role-based access control
- **Scheduled Scanning**: Automated security scans with customizable frequency
- **Agentic Workflows**: Multi-agent security analysis using CrewAI with specialized security agents
- **Adaptive Intelligence**: Query complexity detection to provide appropriate depth of analysis

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- API keys for:
  - Google Gemini AI (required)
  - VirusTotal (optional)
  - WhoisXML (optional)
  - Netlas (optional)
  - NVD (optional)

### Quick Start

1. Clone the repository:
   ```powershell
   git clone https://github.com/your-username/oxsecure-suite.git
   cd oxsecure-suite
   ```

2. Create and activate a virtual environment:
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```

3. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

4. Create a `.env` file with your API keys:
   ```
   GEMINI_API_KEY=your-gemini-api-key
   VIRUSTOTAL_API_KEY=your-virustotal-api-key
   WHOIS_API_KEY=your-whois-api-key
   NETLAS_API_KEY=your-netlas-api-key
   NVD_API_KEY=your-nvd-api-key
   SECRET_KEY=your-jwt-secret-key
   ```

5. Start the server:
   ```powershell
   python app.py
   ```

6. Access the API at `http://localhost:8000`
   - API documentation: `http://localhost:8000/docs`
   - ReDoc interface: `http://localhost:8000/redoc`

## 🔧 Docker Deployment

```powershell
# Build the Docker image
docker build -t oxsecure-suite .

# Run the container
docker run -p 8000:8000 --env-file .env oxsecure-suite
```

## 🧪 Usage Examples

### Authentication

```python
import requests

# Authenticate and get token
auth_response = requests.post(
    "http://localhost:8000/token",
    data={"username": "admin", "password": "OxAadi@123"}
)
token = auth_response.json()["access_token"]

# Use token in subsequent requests
headers = {"Authorization": f"Bearer {token}"}
```

### Domain Analysis

```python
import requests
import json

# Authenticate (see above)
# ...

# Analyze a domain
response = requests.post(
    "http://localhost:8000/api/oxintell/domain-analysis",
    headers=headers,
    json={"domain": "example.com"}
)

# Print formatted results
print(json.dumps(response.json(), indent=2))
```

### Generate Security-Focused Image

```python
import requests
import base64
from PIL import Image
import io

# Authenticate (see above)
# ...

# Generate an image
params = {"prompt": "A visual representation of a cybersecurity defense system"}
response = requests.post(
    "http://localhost:8000/api/oximage/generate",
    headers=headers,
    params=params
)

# Save the generated image
image_data = base64.b64decode(response.json()["image_data"])
image = Image.open(io.BytesIO(image_data))
image.save("security_defense_system.png")
```

## 📚 Documentation

For detailed documentation, please refer to the [documentation.md](documentation.md) file, which includes:

- Complete API reference
- Module details and capabilities
- Authentication system
- Installation and deployment guides
- Troubleshooting

## 🔒 Security Considerations

- Use strong, unique passwords for authentication
- Ensure all API keys are kept secure and not committed to version control
- Update dependencies regularly to patch security vulnerabilities
- Use HTTPS in production environments
- Implement proper rate limiting in production

## 🚀 Roadmap

- Database integration for user management
- Web dashboard for visualization of scan results
- Support for more file types in analysis
- Network traffic analysis capabilities
- Machine learning for anomaly detection
- Container and Kubernetes security scanning

## 📝 License

This project is proprietary software. All rights reserved.

## 👥 Contributors

This project was developed by the OxSecure team.

---

For more information, bug reports, or feature requests, please contact the OxSecure team.
