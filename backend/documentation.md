# OxSecure Suite Technical Documentation

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Authentication System](#authentication-system)
4. [Module Details](#module-details)
5. [API Authentication](#api-authentication)
6. [Installation and Setup](#installation-and-setup)
7. [Testing](#testing)
8. [Usage Examples](#usage-examples)
9. [Error Handling](#error-handling)
10. [Security Considerations](#security-considerations)
11. [Limitations and Considerations](#limitations-and-considerations)
12. [Troubleshooting](#troubleshooting)
13. [Future Development](#future-development)
14. [API Reference](#api-reference)
15. [Contributors](#contributors)
16. [License](#license)

## Project Overview

The OxSecure Suite is a comprehensive security toolkit that combines artificial intelligence with cybersecurity tools to provide intelligent threat detection, analysis, and response capabilities. The suite consists of three main modules:

1. **OxInteLL**: An intelligent security analysis module that offers domain analysis, file analysis, CVE tracking, code scanning, and more
2. **OxRAG**: A Retrieval-Augmented Generation module that provides context-aware analysis of documents, websites, and images
3. **OxImage**: An AI-powered image generation and analysis module for security-related visualizations

The system is built as a FastAPI application with robust authentication, scheduled scanning capabilities, and comprehensive security analysis features using Google's Gemini AI models.

## Architecture

OxSecure Suite follows a modular architecture with a clear separation of concerns:

```
OxSecure Suite/
├── app.py                  # Main entry point and route registration
├── main.py                 # FastAPI app initialization, auth, and core endpoints
├── routes/                 # Module-specific routes
│   ├── __init__.py         # Package marker
│   ├── oxintell.py         # Security intelligence module
│   ├── oxrag.py            # Retrieval-augmented generation module
│   └── oximage.py          # Image generation and analysis module
├── tests/                  # Test files
│   └── test_oxintell_api.py # Tests for OxIntell API
└── requirements.txt        # Project dependencies
```

The application uses the following key technologies:
- **FastAPI**: Modern, high-performance web framework for building APIs
- **Google Gemini AI**: Powerful AI model for text and image analysis
- **JWT Authentication**: Secure token-based authentication system
- **FAISS**: Vector database for efficient similarity search (used in RAG)
- **PyPDF2 & BeautifulSoup**: For extracting text from PDFs and websites
- **DNS & Socket Libraries**: For network and domain analysis

### System Architecture Diagram

```
┌─────────────────┐      ┌─────────────────┐      ┌────────────────────┐
│   Client Apps   │      │  OxSecure API   │      │  External Services │
│  (Web, Mobile)  │◄────►│  (FastAPI App)  │◄────►│  (VirusTotal, etc) │
└─────────────────┘      └────────┬────────┘      └────────────────────┘
                                  │
                         ┌────────┴────────┐
                         │  Authentication │
                         │  (JWT System)   │
                         └────────┬────────┘
                                  │
             ┌─────────────┬──────┴────────┬─────────────┐
             │             │               │             │
      ┌──────▼─────┐ ┌─────▼─────┐  ┌──────▼─────┐ ┌─────▼──────┐
      │  OxInteLL  │ │  OxImage  │  │   OxRAG    │ │  Core API  │
      │   Module   │ │  Module   │  │   Module   │ │  Endpoints │
      └──────┬─────┘ └─────┬─────┘  └──────┬─────┘ └─────┬──────┘
             │             │               │             │
             └─────────────┴───────┬───────┴─────────────┘
                                   │
                          ┌────────▼─────────┐
                          │  Gemini AI Model │
                          └──────────────────┘
```

### Data Flow Architecture

1. Client authenticates via JWT and receives a token
2. Client makes API requests with the auth token
3. FastAPI routes requests to appropriate module
4. Modules perform specialized processing:
   - OxInteLL: Performs security intelligence gathering
   - OxImage: Handles image generation and analysis
   - OxRAG: Manages document and content analysis
5. Modules leverage Google Gemini AI models as needed
6. External APIs are accessed for additional data (VirusTotal, WhoisXML, etc.)
7. Results are processed and returned to the client

## Authentication System

The application implements a JWT-based authentication system with the following features:

- Password hashing using bcrypt
- Token-based authentication with OAuth2PasswordBearer
- Role-based access control
- Token expiration (60 minutes by default)
- Protected routes requiring valid authentication

Auth flow:
1. Client submits username/password to `/token` endpoint
2. Server validates credentials and returns JWT token
3. Client includes token in Authorization header for subsequent requests
4. Server validates token and provides access to protected resources

## Module Details

### 1. OxInteLL Module

The OxInteLL module provides comprehensive security intelligence features through various endpoints:

#### Domain Analysis

**Endpoint**: `/api/oxintell/domain-analysis`  
**Method**: POST  
**Description**: Analyzes a domain name for security information  
**Parameters**:
- `domain`: Domain name to analyze (required)

**Features**:
- WHOIS information retrieval
- DNS record analysis (A, AAAA, NS, MX, TXT records)
- Port scanning for common services
- SSL certificate analysis
- Security score calculation
- Vulnerability detection

#### File Analysis

**Endpoint**: `/api/oxintell/file-analysis`  
**Method**: POST  
**Description**: Analyzes files for potential security threats  
**Parameters**:
- `file`: The file to be analyzed (multipart/form-data)

**Features**:
- File hash calculation (MD5, SHA1, SHA256)
- VirusTotal integration for malware detection
- Metadata extraction
- AI-powered threat assessment

#### CVE Analysis

**Endpoint**: `/api/oxintell/cve-analysis`  
**Method**: POST  
**Description**: Analyzes specific CVE (Common Vulnerabilities and Exposures) entries  
**Parameters**:
- `cve_id`: The CVE ID to analyze (e.g., CVE-2021-44228)

**Features**:
- Retrieves CVE details from National Vulnerability Database
- AI-enhanced explanation of the vulnerability
- Severity assessment
- Mitigation recommendations

#### Recent CVEs

**Endpoint**: `/api/oxintell/recent-cves`  
**Method**: GET  
**Description**: Retrieves recent CVEs from the National Vulnerability Database  
**Parameters**:
- `days`: Number of days to look back (default: 30)
- `max_results`: Maximum number of results to return (default: 40)

#### Security Chat

**Endpoint**: `/api/oxintell/security-chat`  
**Method**: POST  
**Description**: Interactive chat interface for security-related queries  
**Parameters**:
- `query`: Security-related question or topic

#### Code Analysis

**Endpoint**: `/api/oxintell/analyze-code`  
**Method**: POST  
**Description**: Analyzes code for security vulnerabilities  
**Parameters**:
- `file`: Code file to analyze
- `language`: Programming language (optional)

**Features**:
- Static code analysis
- Common vulnerability pattern detection
- Secure coding recommendations
- AI-powered explanation of potential issues

#### Log Analysis

**Endpoint**: `/api/oxintell/analyze-log`  
**Method**: POST  
**Description**: Analyzes log files for security issues  
**Parameters**:
- `file`: Log file to analyze
- `log_type`: Type of log (optional)

**Features**:
- Pattern recognition for security events
- Anomaly detection
- Threat identification
- Remediation recommendations

#### Scheduled Scans

**Endpoint**: `/api/oxintell/schedule-scan`  
**Method**: POST  
**Description**: Schedules an automated security scan  
**Parameters**:
- `scan_type`: Type of scan (domain, code, system)
- `target`: Target to scan
- `frequency`: Scan frequency (hourly, daily, weekly, monthly)
- `notify_email`: Email to notify when scan completes (optional)
- `parameters`: Additional scan parameters (optional)

**Response**:
- `scan_id`: Unique identifier for the scheduled scan
- `scan_type`: Type of scan
- `target`: Target being scanned
- `frequency`: Scan frequency
- `next_scan_time`: Time of the next scheduled scan
- `status`: Current status of the scan

#### List Scheduled Scans

**Endpoint**: `/api/oxintell/scheduled-scans`  
**Method**: GET  
**Description**: Lists all scheduled security scans

#### Scan History

**Endpoint**: `/api/oxintell/scan-history`  
**Method**: GET  
**Description**: Retrieves history of completed security scans  
**Parameters**:
- `days`: Number of days to look back (default: 30)

#### Immediate Scan

**Endpoint**: `/api/oxintell/immediate-scan`  
**Method**: POST  
**Description**: Runs an immediate security scan  
**Parameters**: Same as schedule-scan endpoint

### 2. OxRAG Module

The OxRAG module leverages Retrieval-Augmented Generation to provide context-aware analysis of various content types:

#### Text Analysis

**Endpoint**: `/api/oxrag/analyze/text`  
**Method**: POST  
**Description**: Analyzes text using RAG techniques  
**Parameters**:
- `text`: The text to analyze
- `query`: The specific query to answer based on the text

**Features**:
- Context-aware question answering
- Text chunking for large documents
- Intelligent response generation

#### PDF Analysis

**Endpoint**: `/api/oxrag/analyze/pdf`  
**Method**: POST  
**Description**: Analyzes PDF documents  
**Parameters**:
- `file`: The PDF file to analyze
- `query`: The specific query to answer based on the PDF content

**Features**:
- PDF text extraction
- Structured data analysis
- Query-based information retrieval

#### URL Analysis

**Endpoint**: `/api/oxrag/analyze/url`  
**Method**: POST  
**Description**: Analyzes web content  
**Parameters**:
- `url`: The URL to analyze
- `query`: The specific query to answer based on the website content

**Features**:
- Web scraping and text extraction
- Clean text processing
- Context-relevant response generation

#### Image Analysis with Text

**Endpoint**: `/api/oxrag/analyze/image`  
**Method**: POST  
**Description**: Analyzes images with text queries  
**Parameters**:
- `file`: The image file to analyze
- `query`: The query to answer based on the image

**Features**:
- Image content recognition
- Query-based image analysis
- Detailed explanations of visual elements

### 3. OxImage Module

The OxImage module provides AI-powered image generation and analysis capabilities:

#### Image Generation

**Endpoint**: `/api/oximage/generate`  
**Method**: POST  
**Description**: Generates images based on text prompts  
**Parameters**:
- `prompt`: Description of the image to generate

**Features**:
- High-quality image generation
- Security-focused visualizations
- Base64-encoded image data in response

#### Image Enhancement

**Endpoint**: `/api/oximage/enhance`  
**Method**: POST  
**Description**: Enhances images based on instructions  
**Parameters**:
- `file`: The image file to enhance
- `prompt`: Instructions for enhancement

**Features**:
- Image quality improvement
- Specific modifications based on prompt
- Detailed explanation of enhancements

#### Image Analysis

**Endpoint**: `/api/oximage/analyze`  
**Method**: POST  
**Description**: Analyzes images for content and features  
**Parameters**:
- `file`: The image file to analyze
- `prompt`: Specific analysis instructions or questions

**Features**:
- Detailed image content analysis
- Query-specific insights
- Technical details extraction

## API Authentication

To access protected endpoints, clients must authenticate using the following procedure:

1. Obtain an access token by sending a POST request to the `/token` endpoint with username and password
2. Include the token in the Authorization header of subsequent requests:
   ```
   Authorization: Bearer <access_token>
   ```

Endpoints marked with security requirements (`OAuth2PasswordBearer`) will reject requests without a valid token.

## Installation and Setup

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- A valid Google Gemini API key
- (Optional) VirusTotal API key
- (Optional) WhoisXML API key
- (Optional) Netlas API key
- (Optional) NVD API key

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/oxsecure-suite.git
   cd oxsecure-suite
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file with required API keys:
   ```
   GEMINI_API_KEY=your-gemini-api-key
   VIRUSTOTAL_API_KEY=your-virustotal-api-key
   WHOIS_API_KEY=your-whois-api-key
   NETLAS_API_KEY=your-netlas-api-key
   NVD_API_KEY=your-nvd-api-key
   SECRET_KEY=your-jwt-secret-key
   ```

5. Start the application:
   ```bash
   python app.py
   ```

The API will be accessible at `http://localhost:8000` by default.

### Docker Deployment (Optional)

1. Build the Docker image:
   ```bash
   docker build -t oxsecure-suite .
   ```

2. Run the container:
   ```bash
   docker run -p 8000:8000 --env-file .env oxsecure-suite
   ```

#### Sample Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create necessary directories if needed
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["python", "app.py"]
```

#### Cloud Deployment Considerations

For production environments, consider deploying to a cloud provider:

- **AWS**: Use Elastic Container Service (ECS) or Elastic Kubernetes Service (EKS)
- **Azure**: Use Azure Container Instances or Azure Kubernetes Service (AKS)
- **Google Cloud**: Use Google Kubernetes Engine (GKE) or Cloud Run

Ensure proper configuration of:
- Load balancers for high availability
- TLS/SSL certificates for secure communication
- Environment-specific configuration management
- Persistent storage for data retention
- Continuous integration/continuous deployment (CI/CD) pipelines

## Testing

The project includes test cases for the OxInteLL API. To run the tests:

```bash
pytest tests/
```

Test cases cover:
- Domain analysis functionality
- Scheduled scans
- Immediate scans
- Scan history
- CVE retrieval

## Usage Examples

### Domain Analysis

```python
import requests
import json

# Authenticate
auth_response = requests.post(
    "http://localhost:8000/token",
    data={"username": "admin", "password": "OxAadi@123"}
)
token = auth_response.json()["access_token"]

# Analyze a domain
headers = {"Authorization": f"Bearer {token}"}
response = requests.post(
    "http://localhost:8000/api/oxintell/domain-analysis",
    headers=headers,
    json={"domain": "example.com"}
)

# Print results
print(json.dumps(response.json(), indent=2))
```

### Analyzing a PDF Document

```python
import requests

# Authenticate
auth_response = requests.post(
    "http://localhost:8000/token",
    data={"username": "admin", "password": "OxAadi@123"}
)
token = auth_response.json()["access_token"]

# Analyze a PDF
headers = {"Authorization": f"Bearer {token}"}
files = {"file": open("document.pdf", "rb")}
data = {"query": "What are the main security recommendations in this document?"}

response = requests.post(
    "http://localhost:8000/api/oxrag/analyze/pdf",
    headers=headers,
    files=files,
    data=data
)

# Print results
print(response.json()["response"])
```

### Generating an Image

```python
import requests
import base64
from PIL import Image
import io

# Authenticate
auth_response = requests.post(
    "http://localhost:8000/token",
    data={"username": "admin", "password": "OxAadi@123"}
)
token = auth_response.json()["access_token"]

# Generate an image
headers = {"Authorization": f"Bearer {token}"}
params = {"prompt": "A visual representation of a cybersecurity defense system"}

response = requests.post(
    "http://localhost:8000/api/oximage/generate",
    headers=headers,
    params=params
)

# Save the generated image
image_data = base64.b64decode(response.json()["image_data"])
image = Image.open(io.BytesIO(image_data))
image.save("generated_image.png")
```

## Error Handling

The API uses standardized HTTP status codes and error responses:

- **400 Bad Request**: Invalid input parameters
- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Insufficient permissions
- **404 Not Found**: Resource not found
- **422 Validation Error**: Request validation failed
- **500 Internal Server Error**: Server-side error

Error responses follow this format:
```json
{
  "detail": "Error message or validation details"
}
```

### Exception Handling

The application implements centralized exception handling with custom exception classes:

- `AuthenticationError`: Authentication-related failures
- `ValidationError`: Input validation failures
- `ResourceNotFoundError`: Requested resource not found
- `ExternalAPIError`: Issues with third-party services
- `RateLimitError`: API rate limit reached

Each module uses try-except blocks to catch exceptions and return appropriate HTTP error responses with descriptive messages to help clients troubleshoot issues.

## Security Considerations

- **Password Management**:
  - The application uses bcrypt for password hashing with appropriate work factors
  - Passwords are never stored in plaintext
  - Password policies can be enforced (minimum length, complexity)

- **Authentication & Authorization**:
  - JWT tokens expire after 60 minutes by default (configurable)
  - Tokens use the secure HS256 algorithm
  - Protected endpoints require valid authentication
  - Role-based access controls can be implemented

- **Secure Configurations**:
  - Environment variables are used for sensitive API keys
  - Production deployments should use a .env file or secrets management
  - JWT secret keys should be strong and randomly generated
  - All API keys should be rotated regularly

- **Network Security**:
  - CORS is configured to restrict access to specified origins
  - API rate limiting should be implemented in production
  - Consider using a Web Application Firewall (WAF) in production
  - Use HTTPS for all communications in production environments

- **Input Validation & Sanitization**:
  - Input validation is implemented for all API endpoints
  - Structured data validation using Pydantic models
  - Content-type validation for file uploads
  - Size limits for uploaded files

- **Logging & Monitoring**:
  - Implement comprehensive logging for security events
  - Log authentication attempts, especially failures
  - Monitor unusual API usage patterns
  - Set up alerts for security-critical events

## Limitations and Considerations

- The application currently uses mock users for authentication; implement a proper database in production
- API keys for external services (VirusTotal, WhoisXML, etc.) should be valid in production
- The port scanning functionality may be blocked by firewalls or trigger security alerts
- Consider rate limiting to prevent abuse of API endpoints

## Troubleshooting

Common issues and solutions:

1. **Authentication failures**:
   - Verify username and password
   - Check that JWT secret key is properly set
   - Ensure token is not expired

2. **API key errors**:
   - Verify that all required API keys are set in the .env file
   - Check API key quotas and limits for external services

3. **Performance issues**:
   - Large PDF files may cause timeouts during analysis
   - Complex image generation prompts may take longer to process

## Future Development

Planned enhancements:
- Implement a proper database for user management
- Add support for additional file types in analysis
- Implement a web dashboard for scan results visualization
- Add support for network traffic analysis
- Implement machine learning for anomaly detection
- Add support for container and Kubernetes security scanning

### Performance Optimization Roadmap

Current performance optimizations include:
- Chunking large documents for efficient processing
- Asynchronous API calls to external services
- FAISS for efficient vector similarity search

Future performance improvements:
- **Caching**: Implement Redis or memcached for caching frequently requested data
- **Database Integration**: Move from in-memory storage to a database with proper indexing
- **Task Queues**: Use Celery or similar for handling long-running tasks
- **Horizontal Scaling**: Design for horizontal scalability in high-load environments
- **Optimization of AI Model Calls**: Batch processing and more efficient prompting
- **Image Processing Optimization**: Resize and compress images before AI processing

## API Reference

A complete OpenAPI specification is available at `/docs` when the server is running:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Contributors

This project was developed by the OxSecure team.

## License

This project is proprietary software. All rights reserved.

---

Last updated: June 2024
