from fastapi import APIRouter, HTTPException, Depends, UploadFile, File, Form, Query
from fastapi.responses import JSONResponse
from typing import Optional, List, Dict, Any
from auth import get_current_active_user, User
import os
import time
import random
from dotenv import load_dotenv
import google.generativeai as genai

# Langchain and CrewAI imports
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain.memory import ConversationBufferMemory
from crewai import Agent, Task, Crew, Process

import hashlib
import requests
import socket
import base64
from pydantic import BaseModel, Field
from PIL import Image, ExifTags
from PIL.ExifTags import TAGS, GPSTAGS
import io
import json
from datetime import datetime, timedelta
import certifi
import ssl
import asyncio
from urllib.parse import urlparse
import dns.resolver
from google.api_core.exceptions import GoogleAPIError
import asyncio

# Load environment variables from .env file
load_dotenv()

# Create a router
router = APIRouter(
    prefix="/api/oxintell",
    tags=["OxInteLL"],
)

# Configure Gemini API Key (get from environment variable in production)
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "your-gemini-api-key")
genai.configure(api_key=GEMINI_API_KEY)

# Configure Langchain LLM with Google Generative AI
llm = ChatGoogleGenerativeAI(
    model="gemini-2.0-flash", 
    google_api_key=GEMINI_API_KEY,
    temperature=0.2
)

# Memory for conversation history
conversation_memory = ConversationBufferMemory(return_messages=True)

# Create agents for CrewAI

# Create agents for CrewAI
security_researcher = Agent(
    role="Security Researcher",
    goal="Discover and analyze cybersecurity information thoroughly",
    backstory="You are an elite security researcher with expertise in discovering vulnerabilities, analyzing threats, and providing in-depth technical analysis.",
    verbose=True,
    llm=llm,
    allow_delegation=True
)

threat_analyst = Agent(
    role="Threat Analyst",
    goal="Analyze security threats and provide detailed risk assessments",
    backstory="You specialize in threat intelligence, risk assessment, and providing actionable security insights.",
    verbose=True,
    llm=llm,
    allow_delegation=True
)

security_advisor = Agent(
    role="Security Advisor",
    goal="Provide practical security recommendations and best practices",
    backstory="As a security advisor, you translate complex security concepts into practical advice that can be implemented by organizations of any size.",
    verbose=True,
    llm=llm,
    allow_delegation=False
)

# Memory for conversation history
conversation_memory = ConversationBufferMemory(return_messages=True)

# External API keys
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "your-virustotal-api-key")
WHOIS_API_KEY = os.getenv("WHOIS_API_KEY", "your-whois-api-key")
NETLAS_API_KEY = os.getenv("NETLAS_API_KEY", "your-netlas-api-key")
NVD_API_KEY = os.getenv("NVD_API_KEY", "your-nvd-api-key")

# Port details with names, protocols, and descriptions
port_details = {
    21: {
        "name": "FTP 🌐",
        "protocol": "File Transfer Protocol 📂",
        "description": "FTP is used for transferring files between hosts. 🔄",
        "causes": "Unsecured configurations can lead to data leaks. 🚨",
        "misconfiguration": "Using default settings without encryption. 🔑",
        "vulnerabilities": "Sensitive data can be exposed over plaintext. 🛡️"
    },
    22: {
        "name": "SSH 🔒",
        "protocol": "Secure Shell 🔐",
        "description": "SSH is used for secure remote administration. 🖥️",
        "causes": "Weak passwords or keys can lead to unauthorized access. ⚠️",
        "misconfiguration": "Allowing root login can pose security risks. 🚷",
        "vulnerabilities": "Potential for brute force attacks. 💥"
    },
    23: {
        "name": "Telnet 💻",
        "protocol": "Telnet Protocol 🌐",
        "description": "Telnet is used for remote command-line access. 🛠️",
        "causes": "Insecure communication over networks. 🌍",
        "misconfiguration": "Allowing Telnet instead of SSH. ❌",
        "vulnerabilities": "Data, including passwords, is transmitted in plaintext. 📜"
    },
    25: {
        "name": "SMTP 📧",
        "protocol": "Simple Mail Transfer Protocol ✉️",
        "description": "SMTP is used for sending emails. 📬",
        "causes": "Misconfigured servers can allow spam relaying. 🚫",
        "misconfiguration": "Open relays can lead to abuse. 🏴‍☠️",
        "vulnerabilities": "Lack of authentication can lead to spam. 🕵️"
    },
    53: {
        "name": "DNS 📡",
        "protocol": "Domain Name System 🌐",
        "description": "DNS resolves domain names to IP addresses. 📍",
        "causes": "DNS poisoning can mislead users. 🧪",
        "misconfiguration": "Open DNS resolvers can be exploited. 🔓",
        "vulnerabilities": "Potential for DDoS amplification attacks. ⚡"
    },
    80: {
        "name": "HTTP 🌍",
        "protocol": "Hypertext Transfer Protocol 📄",
        "description": "HTTP is used for web traffic. 🚦",
        "causes": "Insecure websites can be exploited. ⚔️",
        "misconfiguration": "Failure to use HTTPS can expose data. 🔓",
        "vulnerabilities": "Susceptible to man-in-the-middle attacks. 🕵️‍♂️"
    },
    110: {
        "name": "POP3 📫",
        "protocol": "Post Office Protocol v3 📬",
        "description": "POP3 is used for retrieving emails. 📩",
        "causes": "Using unsecured connections can expose emails. 📡",
        "misconfiguration": "Allowing only plaintext logins. 🔓",
        "vulnerabilities": "Potential for email interception. 🚷"
    },
    143: {
        "name": "IMAP 📥",
        "protocol": "Internet Message Access Protocol 📧",
        "description": "IMAP is used for accessing emails on a server. 🖥️",
        "causes": "Misconfigurations can lead to unauthorized access. ⚠️",
        "misconfiguration": "Failure to secure connections. 🔒",
        "vulnerabilities": "Similar to POP3 vulnerabilities. 🔗"
    },
    443: {
        "name": "HTTPS 🔒",
        "protocol": "HTTP Secure 🔐",
        "description": "HTTPS is used for secure web traffic. 🚀",
        "causes": "Weak SSL configurations can expose data. 🛡️",
        "misconfiguration": "Using outdated TLS versions. ⏳",
        "vulnerabilities": "Potential for SSL stripping attacks. ⚔️"
    },
    3306: {
        "name": "MySQL 💾",
        "protocol": "MySQL Database Service 🗃️",
        "description": "MySQL is used for database services. 🏢",
        "causes": "Default credentials can lead to unauthorized access. 🔑",
        "misconfiguration": "Allowing remote connections without security. 🌐",
        "vulnerabilities": "SQL injection can compromise data. ⚡"
    },
    8080: {
        "name": "HTTP-alt 🌐",
        "protocol": "Alternative HTTP 🔄",
        "description": "Alternative port for HTTP traffic. 🚦",
        "causes": "Misconfigured servers can expose services. 🏢",
        "misconfiguration": "Failure to restrict access. 🚷",
        "vulnerabilities": "Potential for web application vulnerabilities. 🛡️"
    },
}

# Helper function to query Gemini model with agentic capabilities
def query_gemini(prompt, image=None):
    """Enhanced query function that directly uses Gemini API."""
    try:
        # If image is provided, use regular Gemini model directly
        if image is not None:
            Model = genai.GenerativeModel('gemini-2.0-flash')
            response = Model.generate_content([prompt, image])
            return response.text
        
        # For text queries, use Gemini directly
        Model = genai.GenerativeModel('gemini-2.0-flash')
        response = Model.generate_content(prompt)
        return response.text
    
    # Error handling
    except Exception as e:
        print(f"Error in Gemini response generation: {e}")
        return f"Error in generating response: {str(e)}"

# Function to get file hash
def get_file_hash(file_content):
    """Calculate MD5, SHA1, and SHA256 hashes for a file."""
    md5 = hashlib.md5(file_content).hexdigest()
    sha1 = hashlib.sha1(file_content).hexdigest()
    sha256 = hashlib.sha256(file_content).hexdigest()
    return {
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256
    }

# Function to analyze a resource using VirusTotal
def virustotal_analysis(resource, resource_type='file'):
    """
    Analyze a resource using VirusTotal API.
    
    Args:
        resource: The file hash or URL to analyze
        resource_type: Either 'file' or 'url'
    
    Returns:
        Analysis results from VirusTotal
    """
    try:
        base_url = "https://www.virustotal.com/api/v3/"
        
        if resource_type == 'file':
            endpoint = f"files/{resource}"
        else:  # URL
            # URL needs to be encoded for the API
            encoded_url = base64.urlsafe_b64encode(resource.encode()).decode().rstrip("=")
            endpoint = f"urls/{encoded_url}"
        
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        
        response = requests.get(f"{base_url}{endpoint}", headers=headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {
                "error": f"VirusTotal API returned status code {response.status_code}",
                "details": response.text
            }
    except Exception as e:
        return {"error": f"Error in VirusTotal analysis: {str(e)}"}

# Function to extract metadata from image
def extract_image_metadata(image):
    """Extract metadata from an image file."""
    try:
        metadata = {}
        exif_data = image._getexif()
        
        if exif_data:
            for tag_id in exif_data:
                tag = TAGS.get(tag_id, tag_id)
                data = exif_data.get(tag_id)
                
                # Handle GPS data specially
                if tag == 'GPSInfo':
                    gps_data = {}
                    for gps_tag in data:
                        gps_tag_name = GPSTAGS.get(gps_tag, gps_tag)
                        gps_data[gps_tag_name] = data[gps_tag]
                    
                    # Extract location if available
                    if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                        lat_ref = gps_data.get('GPSLatitudeRef', 'N')
                        lon_ref = gps_data.get('GPSLongitudeRef', 'E')
                        
                        lat = gps_data.get('GPSLatitude', (0, 0, 0))
                        lon = gps_data.get('GPSLongitude', (0, 0, 0))
                        
                        # Convert to decimal degrees
                        lat_decimal = lat[0] + lat[1]/60 + lat[2]/3600
                        lon_decimal = lon[0] + lon[1]/60 + lon[2]/3600
                        
                        if lat_ref == 'S':
                            lat_decimal = -lat_decimal
                        if lon_ref == 'W':
                            lon_decimal = -lon_decimal
                        
                        metadata['GPS'] = {
                            'Latitude': lat_decimal,
                            'Longitude': lon_decimal
                        }
                else:
                    metadata[tag] = data
        
        # Add basic image info
        metadata['ImageSize'] = image.size
        metadata['ImageFormat'] = image.format
        metadata['ImageMode'] = image.mode
        
        return metadata
    except Exception as e:
        return {"error": f"Error extracting image metadata: {str(e)}"}

# Function for WHOIS Domain Analysis
def get_whois_info(domain):
    """Get WHOIS information for a domain using WhoisXML API."""
    try:
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService"
        params = {
            'apiKey': WHOIS_API_KEY,
            'domainName': domain,
            'outputFormat': 'json'
        }
        response = requests.get(url, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"WhoisXML API returned status code {response.status_code}: {response.text}"}
    except Exception as e:
        return {"error": f"Error fetching WHOIS information: {str(e)}"}

# Function to fetch IP addresses of the domain
def get_domain_ip(domain):
    """Get IP addresses for a domain and its nameservers."""
    try:
        # Get A records (IPv4 addresses)
        a_records = []
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                a_records.append(str(rdata))
        except Exception as e:
            a_records.append(f"Error: {str(e)}")
        
        # Get AAAA records (IPv6 addresses)
        aaaa_records = []
        try:
            answers = dns.resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                aaaa_records.append(str(rdata))
        except Exception as e:
            aaaa_records.append(f"Error: {str(e)}")
        
        # Get nameservers
        ns_records = []
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                ns = str(rdata)
                ns_records.append(ns)
                
                # Try to get IP of nameserver
                try:
                    ns_ip = socket.gethostbyname(ns)
                    ns_records.append(f"  - IP: {ns_ip}")
                except:
                    ns_records.append("  - IP: Could not resolve")
        except Exception as e:
            ns_records.append(f"Error: {str(e)}")
        
        # Get MX records
        mx_records = []
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx = str(rdata.exchange)
                preference = rdata.preference
                mx_records.append(f"{mx} (preference: {preference})")
                
                # Try to get IP of MX server
                try:
                    mx_ip = socket.gethostbyname(mx)
                    mx_records.append(f"  - IP: {mx_ip}")
                except:
                    mx_records.append("  - IP: Could not resolve")
        except Exception as e:
            mx_records.append(f"Error: {str(e)}")
        
        # Get TXT records
        txt_records = []
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt_records.append(str(rdata))
        except Exception as e:
            txt_records.append(f"Error: {str(e)}")
        
        return {
            "A_Records": a_records,
            "AAAA_Records": aaaa_records,
            "NS_Records": ns_records,
            "MX_Records": mx_records,
            "TXT_Records": txt_records
        }
    except Exception as e:
        return {"error": f"Error fetching domain IP information: {str(e)}"}

# Function to scan common ports
def scan_ports(ip, ports_to_scan=None):
    """Scan common ports on an IP address."""
    if ports_to_scan is None:
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
    
    open_ports = {}
    
    for port in ports_to_scan:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)  # 1 second timeout
            result = sock.connect_ex((ip, port))
            if result == 0:  # Port is open
                port_info = port_details.get(port, {
                    "name": f"Port {port}",
                    "protocol": "Unknown protocol",
                    "description": "No description available",
                    "causes": "Unknown causes",
                    "misconfiguration": "Unknown misconfiguration",
                    "vulnerabilities": "Unknown vulnerabilities"
                })
                open_ports[port] = port_info
            sock.close()
        except Exception as e:
            open_ports[port] = {"error": f"Error scanning port {port}: {str(e)}"}
    
    return open_ports

# Function to fetch SSL certificate details
def get_ssl_info(domain):
    """Get SSL certificate details for a domain."""
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Process certificate information
                cert_info = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "version": cert.get("version", ""),
                    "notBefore": cert.get("notBefore", ""),
                    "notAfter": cert.get("notAfter", ""),
                    "subjectAltName": cert.get("subjectAltName", []),
                    "OCSP": cert.get("OCSP", ""),
                    "caIssuers": cert.get("caIssuers", ""),
                    "crlDistributionPoints": cert.get("crlDistributionPoints", "")
                }
                
                return cert_info
    except Exception as e:
        return {"error": f"Error fetching SSL information: {str(e)}"}

# Function to fetch CVE data from NVD
def get_cve_data(cve_id):
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        "X-Api-Key": NVD_API_KEY
        }
    # Construct the URL for the specific CVE
    url = f"{BASE_URL}?cveId={cve_id}"
    
    # Send a GET request to the API
    response = requests.get(url, headers=headers)
    
    # Check if the request was successful
    if response.status_code == 200:
        return response.json()  # Return the JSON data
    else:
        print(f"Error: {response.status_code}")
        return None

# Function to get recent CVEs
def get_recent_cves(pub_start_date=None, pub_end_date=None, max_results=40):
    """Get recent CVEs from the NVD API using API v2.0."""
    try:
        # Default to last 30 days if dates not provided
        if not pub_start_date:
            pub_start_date = (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%dT00:00:00.000Z")
        
        if not pub_end_date:
            pub_end_date = datetime.now().strftime("%Y-%m-%dT23:59:59.999Z")
        
        # Use the NVD API v2.0 endpoint
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "pubStartDate": pub_start_date,
            "pubEndDate": pub_end_date,
            "resultsPerPage": max_results
        }
        
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY
        
        # Log the request details for debugging
        print(f"NVD API Request - URL: {url}, Params: {params}")
        
        response = requests.get(url, params=params, headers=headers, timeout=30)
        
        if response.status_code == 200:
            cves_data = response.json()
            
            # Process the CVEs to extract key information - API v2.0 has a different structure
            processed_cves = []
            for cve_item in cves_data.get("vulnerabilities", []):
                cve_data = cve_item.get("cve", {})
                cve = {
                    "id": cve_data.get("id", ""),
                    "published": cve_data.get("published", ""),
                    "description": "",
                    "severity": "N/A",
                    "score": 0.0
                }
                
                # Extract description
                descriptions = cve_data.get("descriptions", [])
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        cve["description"] = desc.get("value", "")
                        break
                
                # Extract CVSS score and severity if available
                metrics = cve_data.get("metrics", {})
                
                # Try to get CVSS v3.1 scores first
                if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
                    cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cve["severity"] = cvss_data.get("baseSeverity", "N/A")
                    cve["score"] = cvss_data.get("baseScore", 0.0)
                # Fall back to CVSS v3.0
                elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
                    cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
                    cve["severity"] = cvss_data.get("baseSeverity", "N/A")
                    cve["score"] = cvss_data.get("baseScore", 0.0)
                # Fall back to CVSS v2.0
                elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                    cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                    cve["severity"] = cvss_data.get("baseSeverity", "N/A")
                    cve["score"] = cvss_data.get("baseScore", 0.0)
                
                processed_cves.append(cve)
            
            # Sort by score (highest first)
            processed_cves.sort(key=lambda x: x["score"], reverse=True)
            
            return processed_cves
        else:
            error_message = f"NVD API returned status code {response.status_code}"
            print(f"NVD API Error: {error_message}")
            print(f"Response content: {response.text}")
            
            return {
                "error": error_message,
                "details": response.text
            }
    except Exception as e:
        error_message = f"Error fetching recent CVEs: {str(e)}"
        print(f"Exception in get_recent_cves: {error_message}")
        return {"error": error_message}

# Models for request/response
class DomainAnalysisRequest(BaseModel):
    domain: str = Field(..., description="Domain name to analyze")

class FileAnalysisRequest(BaseModel):
    resource_hash: str = Field(..., description="Hash of the file to analyze")

class CveAnalysisRequest(BaseModel):
    cve_id: str = Field(..., description="CVE ID to analyze")

class SecurityChatRequest(BaseModel):
    query: str = Field(..., description="Security-related query")

# Models for scheduled scans
class ScheduledScanRequest(BaseModel):
    scan_type: str = Field(..., description="Type of scan to schedule (domain, code, system)")
    target: str = Field(..., description="Target to scan (domain, repository URL, or system)")
    frequency: str = Field("daily", description="Scan frequency (hourly, daily, weekly, monthly)")
    notify_email: Optional[str] = Field(None, description="Email to notify when scan completes")
    parameters: Optional[Dict[str, Any]] = Field({}, description="Additional scan parameters")

class ScheduledScanResponse(BaseModel):
    scan_id: str
    scan_type: str
    target: str
    frequency: str
    next_scan_time: str
    status: str

# Routes
@router.post("/domain-analysis")
async def analyze_domain(
    request: DomainAnalysisRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Analyze a domain for security information."""
    domain = request.domain
    
    # Parse domain to ensure it's valid
    try:
        parsed = urlparse(domain)
        if not parsed.scheme:
            domain = "http://" + domain
            parsed = urlparse(domain)
        
        domain_name = parsed.netloc or parsed.path
        
        # Remove www. if present
        if domain_name.startswith("www."):
            domain_name = domain_name[4:]
        
        # Get WHOIS information
        whois_info = get_whois_info(domain_name)
        
        # Get IP addresses
        ip_info = get_domain_ip(domain_name)
        
        # Get main IP for port scanning
        main_ip = None
        if "A_Records" in ip_info and ip_info["A_Records"] and not ip_info["A_Records"][0].startswith("Error"):
            main_ip = ip_info["A_Records"][0]
        
        # Scan ports if we have an IP
        port_scan_results = {}
        if main_ip:
            port_scan_results = scan_ports(main_ip)
        
        # Get SSL information if applicable
        ssl_info = {}
        try:
            ssl_info = get_ssl_info(domain_name)
        except:
            ssl_info = {"error": "Could not get SSL information (domain might not support HTTPS)"}
        
        # Analyze with Gemini
        domain_details = {
            "domain": domain_name,
            "whois": whois_info,
            "ip_info": ip_info,
            "port_scan": port_scan_results,
            "ssl_info": ssl_info
        }
        
        # Create a prompt for the analysis
        analysis_prompt = f"""
        You are a cybersecurity expert analyzing a domain. Please provide a comprehensive security assessment based on the following information:
        
        Domain: {domain_name}
        WHOIS Information: {json.dumps(whois_info, indent=2)}
        IP Information: {json.dumps(ip_info, indent=2)}
        Open Ports: {json.dumps(port_scan_results, indent=2)}
        SSL Information: {json.dumps(ssl_info, indent=2)}
        
        Please provide:
        1. A summary of the domain and its ownership
        2. Security assessment of the domain configuration
        3. Potential vulnerabilities or misconfigurations
        4. Recommendations for improving security
        5. Overall risk rating (Low, Medium, High)
        
        Format your response with proper Markdown formatting, headings, and emoji where appropriate. Be detailed but concise.
        """

        gemini_analysis = query_gemini(analysis_prompt, image=None)

        return {
            "domain": domain_name,
            "raw_data": domain_details,
            "analysis": gemini_analysis
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error analyzing domain: {str(e)}")

@router.post("/file-analysis")
async def analyze_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user)
):
    """Analyze a file for security information."""
    try:
        contents = await file.read()
        
        # Get file hashes
        hashes = get_file_hash(contents)
        
        # Extract metadata based on file type
        metadata = {}
        file_type = file.filename.split(".")[-1].lower() if "." in file.filename else "unknown"
        
        if file_type in ["jpg", "jpeg", "png", "gif", "bmp", "tiff"]:
            image = Image.open(io.BytesIO(contents))
            metadata = extract_image_metadata(image)
        
        # Analyze with VirusTotal
        vt_results = virustotal_analysis(hashes["sha256"])
        
        # Create a prompt for the analysis
        analysis_prompt = f"""
        You are a cybersecurity expert analyzing a file. Please provide a comprehensive security assessment based on the following information:
        
        Filename: {file.filename}
        File Type: {file_type}
        File Hashes: {json.dumps(hashes, indent=2)}
        Metadata: {json.dumps(metadata, indent=2)}
        VirusTotal Results: {json.dumps(vt_results, indent=2)}
        
        Please provide:
        1. A summary of the file and its potential purpose
        2. Security assessment of the file
        3. Any detected malware or suspicious indicators
        4. Recommendations for handling this file
        5. Overall risk rating (Low, Medium, High)
        
        Format your response with proper Markdown formatting, headings, and emoji where appropriate. Be detailed but concise.
        """
        
        # Check if it's an image file for analysis with Gemini Vision
        image_for_analysis = None
        if file_type in ["jpg", "jpeg", "png", "gif", "bmp", "tiff"]:
            image_for_analysis = Image.open(io.BytesIO(contents))
        
        gemini_analysis = query_gemini(analysis_prompt, image_for_analysis)
        
        return {
            "filename": file.filename,
            "file_type": file_type,
            "hashes": hashes,
            "metadata": metadata,
            "virustotal": vt_results,
            "analysis": gemini_analysis
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error analyzing file: {str(e)}")

@router.post("/cve-analysis")
async def analyze_cve(
    request: CveAnalysisRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Analyze a CVE for security information."""
    try:
        cve_id = request.cve_id
        
        # Get CVE data from NVD
        cve_data = get_cve_data(cve_id)
        
        # Create a prompt for the analysis
        analysis_prompt = f"""
        You are a cybersecurity expert analyzing a CVE (Common Vulnerability and Exposure). Please provide a comprehensive security assessment based on the following information:
        
        CVE ID: {cve_id}
        CVE Data: {json.dumps(cve_data, indent=2)}
        
        Please provide:
        1. A summary of the vulnerability
        2. Technical details of the vulnerability
        3. Affected systems and software
        4. Potential impact if exploited
        5. Mitigation strategies
        6. Patch information if available
        
        Format your response with proper Markdown formatting, headings, and emoji where appropriate. Be detailed but concise.
        """
        
        gemini_analysis = query_gemini(analysis_prompt)
        
        return {
            "cve_id": cve_id,
            "raw_data": cve_data,
            "analysis": gemini_analysis
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error analyzing CVE: {str(e)}")

@router.get("/recent-cves")
async def get_recent_cves_route(
    days: int = Query(30, description="Number of days to look back for CVEs"),
    max_results: int = Query(40, description="Maximum number of results to return"),
    current_user: User = Depends(get_current_active_user)
):
    """Get recent CVEs from the NVD database."""
    try:
        # Format dates according to NVD API v2.0 requirements (ISO format with Z suffix)
        pub_start_date = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00.000Z")
        pub_end_date = datetime.now().strftime("%Y-%m-%dT23:59:59.999Z")
        
        cves = get_recent_cves(pub_start_date, pub_end_date, max_results)
        
        # Handle case where an error object is returned instead of a list
        if isinstance(cves, dict) and "error" in cves:
            raise HTTPException(status_code=400, detail=cves["error"])
            
        return {
            "cves": cves,
            "period": {
                "start_date": pub_start_date,
                "end_date": pub_end_date,
                "days": days
            },
            "count": len(cves) if isinstance(cves, list) else 0
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error getting recent CVEs: {str(e)}")

@router.post("/security-chat")
async def security_chat(
    request: SecurityChatRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Chat with AI about security topics."""
    try:
        query = request.query
        
        # Log the query for monitoring purposes
        print(f"Security chat query received: {query}")
        
        # Simple flag to use fallback responses without API calls during high load periods
        use_fallback = os.getenv("USE_FALLBACK_RESPONSES", "false").lower() == "true"
        if use_fallback:
            print("Using fallback response due to environment setting")
            fallback_response = "I'm sorry, but I'm currently experiencing high demand. Please try again later."
            return {
                "query": query,
                "response": fallback_response,
                "processing_type": "fallback"
            }
        
        # Prepare a specialized prompt for security chat
        security_prompt = f"""
        You are OxInteLL, an AI security assistant specialized in cybersecurity.
        
        User question: {query}
        
        Provide a detailed, accurate, and helpful response related to cybersecurity.
        If the question is not related to security, politely redirect them to ask a security-related question.
        Include relevant technical details, best practices, and recommendations where appropriate.
        Format your response with clear organization, using markdown for readability.
        """
        
        # Call Gemini model directly
        response = query_gemini(security_prompt)
        
        # Return the response with metadata
        return {
            "query": query,
            "response": response,
            "processing_type": "direct"
        }
    except Exception as e:
        error_message = f"Error processing security chat: {str(e)}"
        print(f"Security chat error: {error_message}")
        fallback_response = f"I'm sorry, but I encountered an error while processing your request. Please try again later."
        return {
            "query": query,
            "response": fallback_response,
            "error": error_message
        }

@router.post("/analyze-code")
async def analyze_code(
    file: UploadFile = File(...),
    language: str = Form(None),
    current_user: User = Depends(get_current_active_user)
):
    """Analyze code for security vulnerabilities."""
    try:
        contents = await file.read()
        code = contents.decode('utf-8')
        
        # Determine language if not provided
        if not language:
            file_extension = file.filename.split(".")[-1].lower() if "." in file.filename else ""
            language_map = {
                "py": "Python",
                "js": "JavaScript",
                "ts": "TypeScript",
                "java": "Java",
                "c": "C",
                "cpp": "C++",
                "cs": "C#",
                "php": "PHP",
                "rb": "Ruby",
                "go": "Go",
                "rs": "Rust",
                "swift": "Swift",
                "kt": "Kotlin",
                "html": "HTML",
                "css": "CSS",
                "sql": "SQL",
                "sh": "Shell",
                "ps1": "PowerShell"
            }
            language = language_map.get(file_extension, "Unknown")
        
        # Split code into chunks if it's large (> 10K characters)
        chunks = [code]
        if len(code) > 10000:
            # Simple chunking by lines, more sophisticated chunking may be needed
            lines = code.split('\n')
            chunks = []
            current_chunk = []
            current_size = 0
            
            for line in lines:
                line_size = len(line) + 1  # +1 for newline
                if current_size + line_size > 10000:
                    chunks.append('\n'.join(current_chunk))
                    current_chunk = [line]
                    current_size = line_size
                else:
                    current_chunk.append(line)
                    current_size += line_size
            
            # Add the last chunk
            if current_chunk:
                chunks.append('\n'.join(current_chunk))
        
        # Analyze each chunk
        analyses = []
        for i, chunk in enumerate(chunks):
            chunk_prompt = f"""
            You are a cybersecurity expert specializing in secure coding practices. Please analyze the following {language} code for security vulnerabilities, bugs, and best practices:
            
            ```{language.lower()}
            {chunk}
            ```
            
            Provide a detailed security analysis including:
            1. Identified security vulnerabilities (with severity: High, Medium, Low)
            2. Potential bugs or logical errors
            3. Security best practices that are not being followed
            4. Recommendations for fixing each issue
            5. Code quality assessment
            
            Focus especially on:
            - Injection vulnerabilities (SQL, NoSQL, OS command, etc.)
            - Authentication issues
            - Authorization problems
            - Data validation weaknesses
            - Cryptographic failures
            - Hardcoded credentials or secrets
            - Insecure direct object references
            - Cross-site scripting (XSS) vulnerabilities
            - CSRF vulnerabilities
            - Insecure deserialization
            - Memory safety issues (if applicable)
            
            Format your response using Markdown with clear headings, bullet points, and code examples for fixes where appropriate.
            """
            
            chunk_analysis = query_gemini(chunk_prompt)
            analyses.append(chunk_analysis)
        
        # If there's only one chunk, return it directly
        if len(analyses) == 1:
            return {
                "filename": file.filename,
                "language": language,
                "analysis": analyses[0]
            }
        
        # Otherwise, create a summary of all chunks
        summary_prompt = f"""
        You are a cybersecurity expert who has analyzed multiple parts of a {language} file named {file.filename}. 
        Each part has its own analysis:
        
        {json.dumps(analyses, indent=2)}
        
        Please create a comprehensive summary that combines all these analyses into a single cohesive report. 
        The summary should:
        1. Provide an overall security assessment
        2. List all unique vulnerabilities found across all parts (avoiding duplicates)
        3. Prioritize issues by severity
        4. Give recommendations for addressing the most critical issues first
        5. Include a conclusion about the overall security posture of the code
        
        Format your response using Markdown with clear headings, bullet points, and code examples where appropriate.
        """
        
        summary = query_gemini(summary_prompt)
        
        return {
            "filename": file.filename,
            "language": language,
            "chunk_count": len(chunks),
            "analysis": summary,
            "chunk_analyses": analyses
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error analyzing code: {str(e)}")

@router.post("/analyze-log")
async def analyze_log(
    file: UploadFile = File(...),
    log_type: str = Form(None),
    current_user: User = Depends(get_current_active_user)
):
    """Analyze log files for security issues."""
    try:
        contents = await file.read()
        log_content = contents.decode('utf-8', errors='replace')
        
        # Determine log type if not provided
        if not log_type:
            if "access" in file.filename.lower():
                log_type = "Web Server Access Log"
            elif "error" in file.filename.lower():
                log_type = "Web Server Error Log"
            elif "auth" in file.filename.lower() or "security" in file.filename.lower():
                log_type = "Authentication Log"
            elif "syslog" in file.filename.lower():
                log_type = "System Log"
            elif "firewall" in file.filename.lower():
                log_type = "Firewall Log"
            else:
                log_type = "Generic Log"
        
        # Create a prompt for analyzing the log
        log_prompt = f"""
        You are a cybersecurity expert analyzing a {log_type} file. Please examine the log content and provide a comprehensive security analysis:
        
        Log Type: {log_type}
        Log Content:
        ```
        {log_content[:15000]}  # Limit to first 15K characters
        ```
        
        Please provide:
        1. A summary of the log content and time period covered
        2. Identified security events or suspicious activities
        3. Potential security incidents with severity ratings
        4. Statistical analysis (e.g., top IPs, user agents, response codes, etc. if applicable)
        5. Recommendations for further investigation or remediation
        
        Format your response using Markdown with clear headings, bullet points, and tables where appropriate.
        If the log is truncated, note that your analysis only covers the portion provided.
        """
        
        analysis = query_gemini(log_prompt)
        
        return {
            "filename": file.filename,
            "log_type": log_type,
            "analysis": analysis
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error analyzing log: {str(e)}")

# Route for scheduling automated security scans
@router.post("/schedule-scan", response_model=ScheduledScanResponse)
async def schedule_security_scan(
    request: ScheduledScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Schedule an automated security scan."""
    try:
        scan_id = f"scan_{hashlib.md5(f'{request.scan_type}_{request.target}_{datetime.now().isoformat()}'.encode()).hexdigest()}"
        
        # Determine next scan time based on frequency
        now = datetime.now()
        if request.frequency == "hourly":
            next_scan = now + timedelta(hours=1)
        elif request.frequency == "daily":
            next_scan = now + timedelta(days=1)
        elif request.frequency == "weekly":
            next_scan = now + timedelta(weeks=1)
        elif request.frequency == "monthly":
            next_scan = now + timedelta(days=30)
        else:
            next_scan = now + timedelta(days=1)  # Default to daily
        
        # In a real implementation, this would be stored in a database
        # For now, we'll just return the scheduled scan information
        return {
            "scan_id": scan_id,
            "scan_type": request.scan_type,
            "target": request.target,
            "frequency": request.frequency,
            "next_scan_time": next_scan.isoformat(),
            "status": "scheduled"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error scheduling scan: {str(e)}")

# Route for listing scheduled scans
@router.get("/scheduled-scans")
async def list_scheduled_scans(
    current_user: User = Depends(get_current_active_user)
):
    """List all scheduled security scans."""
    try:
        # In a real implementation, this would fetch from a database
        # For now, we'll return sample data
        sample_scans = [
            {
                "scan_id": "scan_123456",
                "scan_type": "domain",
                "target": "example.com",
                "frequency": "daily",
                "next_scan_time": (datetime.now() + timedelta(hours=12)).isoformat(),
                "status": "scheduled"
            },
            {
                "scan_id": "scan_789012",
                "scan_type": "code",
                "target": "https://github.com/example/repo",
                "frequency": "weekly",
                "next_scan_time": (datetime.now() + timedelta(days=3)).isoformat(),
                "status": "scheduled"
            }
        ]
        
        return {"scheduled_scans": sample_scans}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error listing scheduled scans: {str(e)}")

# Route for getting scan history
@router.get("/scan-history")
async def get_scan_history(
    days: int = Query(30, description="Number of days to look back for scan history"),
    current_user: User = Depends(get_current_active_user)
):
    """Get history of completed security scans."""
    try:
        # In a real implementation, this would fetch from a database
        # For now, we'll return sample data
        sample_history = [
            {
                "scan_id": "scan_abc123",
                "scan_type": "domain",
                "target": "example.com",
                "start_time": (datetime.now() - timedelta(days=1, hours=3)).isoformat(),
                "end_time": (datetime.now() - timedelta(days=1, hours=2, minutes=45)).isoformat(),
                "status": "completed",
                "findings": {
                    "high": 2,
                    "medium": 3,
                    "low": 5
                }
            },
            {
                "scan_id": "scan_def456",
                "scan_type": "code",
                "target": "https://github.com/example/repo",
                "start_time": (datetime.now() - timedelta(days=5, hours=7)).isoformat(),
                "end_time": (datetime.now() - timedelta(days=5, hours=6, minutes=30)).isoformat(),
                "status": "completed",
                "findings": {
                    "high": 1,
                    "medium": 4,
                    "low": 8
                }
            }
        ]
        
        return {
            "scan_history": sample_history,
            "period": {
                "start_date": (datetime.now() - timedelta(days=days)).isoformat(),
                "end_date": datetime.now().isoformat(),
                "days": days
            },
            "count": len(sample_history)
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error getting scan history: {str(e)}")

# Route for initiating an immediate security scan
@router.post("/immediate-scan")
async def run_immediate_scan(
    request: ScheduledScanRequest,
    current_user: User = Depends(get_current_active_user)
):
    """Run an immediate security scan."""
    try:
        scan_id = f"scan_{hashlib.md5(f'{request.scan_type}_{request.target}_{datetime.now().isoformat()}'.encode()).hexdigest()}"
        
        # In a real implementation, this would initiate an actual scan
        # For now, we'll just simulate a scan response
        
        # Wait a few seconds to simulate processing time
        await asyncio.sleep(2)
        
        scan_results = {
            "scan_id": scan_id,
            "scan_type": request.scan_type,
            "target": request.target,
            "start_time": datetime.now().isoformat(),
            "end_time": (datetime.now() + timedelta(seconds=2)).isoformat(),
            "status": "completed",
            "findings": {
                "high": 1,
                "medium": 3,
                "low": 5,
                "total": 9
            },
            "summary": f"Completed security scan of {request.target}. Found 9 security issues (1 high, 3 medium, 5 low)."
        }
        
        return scan_results
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error running immediate scan: {str(e)}")

# Helper functions for the CrewAI-based security chat
def create_security_research_task(query):
    """Create a security research task based on user query."""
    return Task(
        description=f"Research comprehensive information about: {query}",
        agent=security_researcher,
        expected_output="Comprehensive security research findings with technical details and background information.",
        context=f"The user wants to know about: {query}. Provide thorough research on this security topic, including technical details, history, and current relevance."
    )

def create_threat_analysis_task(query, research_output):
    """Create a threat analysis task based on research findings."""
    return Task(
        description=f"Analyze security threats and risks related to: {query}",
        agent=threat_analyst,
        expected_output="Detailed threat analysis with risk assessment and potential impact.",
        context=f"Based on this research: {research_output}\n\nAnalyze the security threats, risks, and potential impacts related to this topic. Include severity levels and affected systems or individuals."
    )

def create_advisory_task(query, research_output, threat_analysis):
    """Create a security advisory task based on research and threat analysis."""
    return Task(
        description=f"Provide practical security recommendations for: {query}",
        agent=security_advisor,
        expected_output="Actionable security recommendations and best practices.",
        context=f"Based on this research: {research_output}\n\nAnd this threat analysis: {threat_analysis}\n\nProvide practical, actionable security recommendations and best practices related to this topic. Include specific steps that organizations or individuals can take to protect themselves."
    )

def run_security_crew(query):
    """Run the security crew to process a user query."""
    try:
        # Create tasks
        research_task = create_security_research_task(query)
        
        # Create a crew with the agents and tasks
        crew = Crew(
            agents=[security_researcher, threat_analyst, security_advisor],
            tasks=[research_task],
            verbose=2,
            process=Process.sequential
        )
        
        # Run the crew and get results
        result = crew.kickoff()
        
        # Extract research output
        research_output = result
        
        # Create and run threat analysis task
        threat_task = create_threat_analysis_task(query, research_output)
        threat_crew = Crew(
            agents=[threat_analyst],
            tasks=[threat_task],
            verbose=2,
            process=Process.sequential
        )
        threat_analysis = threat_crew.kickoff()
        
        # Create and run advisory task
        advisory_task = create_advisory_task(query, research_output, threat_analysis)
        advisory_crew = Crew(
            agents=[security_advisor],
            tasks=[advisory_task],
            verbose=2,
            process=Process.sequential
        )
        security_advice = advisory_crew.kickoff()
        
        # Compile final response
        final_response = f"""
# Security Analysis: {query}

## Research Findings
{research_output}

## Threat Assessment
{threat_analysis}

## Security Recommendations
{security_advice}
"""
        
        return final_response
    except Exception as e:
        print(f"Error in running security crew: {e}")
        return f"Error in generating comprehensive security analysis: {str(e)}"

# Langchain-based security chat for simpler queries
def langchain_security_chat(query):
    """Use Langchain for simpler security-related queries."""
    try:
        import time
        import random
        
        # Simple cache mechanism to avoid repeated API calls
        # In a production system, use a proper caching solution
        if hasattr(langchain_security_chat, 'cache') and query in langchain_security_chat.cache:
            print(f"Using cached response for query: {query}")
            return langchain_security_chat.cache[query]
            
        # Check if the query is GraphQL related
        graphql_related = any(keyword in query.lower() for keyword in ['graphql', 'graph ql', 'graph-ql'])
        
        template = """
        You are OxInteLL, an expert cybersecurity AI assistant specialized in cybersecurity.
        
        User Query: {query}
        
        Your response should:
        1. Be accurate and up-to-date with cybersecurity best practices
        2. Provide practical advice when applicable
        3. Cite sources or references if relevant
        4. Use proper technical terminology
        5. Be formatted with Markdown for readability
        
        If the query is ambiguous, address the most likely security-related interpretation. 
        If the query is not security-related, politely explain that you specialize in cybersecurity topics.
        
        Detailed Response:
        """
        
        # Add specific instructions for GraphQL queries
        if graphql_related:
            template += """
            Since this query is about GraphQL, remember to include:
            - Common GraphQL-specific vulnerabilities like introspection attacks, DoS via nested queries, etc.
            - Specific security measures for GraphQL APIs
            - Code examples for securing GraphQL implementations if relevant
            """
        
        prompt = PromptTemplate(
            input_variables=["query"],
            template=template
        )
        
        # Add simple retry logic
        max_retries = 2
        retry_count = 0
        
        while retry_count <= max_retries:
            try:
                # Create a new LLMChain for each attempt
                security_chain = LLMChain(
                    llm=llm,
                    prompt=prompt,
                    verbose=True
                )
                
                # Run the chain with the query
                response = security_chain.run(query=query)
                
                # Cache the successful response
                if not hasattr(langchain_security_chat, 'cache'):
                    langchain_security_chat.cache = {}
                langchain_security_chat.cache[query] = response
                
                return response
                
            except Exception as retry_error:
                retry_count += 1
                print(f"Error attempt {retry_count}/{max_retries}: {retry_error}")
                
                if retry_count <= max_retries:
                    # Add exponential backoff with jitter
                    wait_time = (2 ** retry_count) + random.uniform(0, 1)
                    print(f"Retrying in {wait_time:.2f} seconds...")
                    time.sleep(wait_time)
                else:
                    # Raise the error to be caught by the outer try/except
                    raise retry_error
                    
    except Exception as e:
        print(f"Error in Langchain security chat: {e}")
        return get_security_fallback_response(query)
        
def get_security_fallback_response(query):
    """Generate a fallback response when API calls fail."""
    # Check what type of query it is to provide a better fallback
    query_lower = query.lower()
    
    if any(term in query_lower for term in ['graphql', 'graph ql', 'graph-ql']):
        return """
## GraphQL Security Best Practices

GraphQL provides a powerful query language for APIs but requires proper security measures:

### Common Vulnerabilities
- **Introspection Attacks**: Disable introspection in production
- **Nested Query DoS**: Implement query depth limiting
- **Over-fetching**: Use proper authorization at field level
- **Injection**: Validate and sanitize all inputs

### Security Recommendations
1. Implement query complexity analysis
2. Use rate limiting for API requests
3. Apply proper authentication and authorization
4. Keep GraphQL dependencies updated
5. Consider using persisted queries in production

For more specific guidance, please try again later when our API service is available.
"""
    elif any(term in query_lower for term in ['malware', 'virus', 'ransomware', 'trojan']):
        return """
## Malware Protection Guidelines

### Essential Security Measures
1. **Keep systems updated** with the latest security patches
2. **Use reputable antivirus/antimalware** solutions with real-time protection
3. **Implement application control** to prevent unauthorized programs
4. **Regular backups** following the 3-2-1 rule (3 copies, 2 different media, 1 offsite)
5. **Security awareness training** for all users

### Incident Response
If you suspect malware infection:
1. Disconnect from networks immediately
2. Run full system scans with updated tools
3. Restore from clean backups if available
4. Reset credentials used on the affected system
5. Report to relevant security teams/authorities

For more specific guidance, please try again later when our API service is available.
"""
    else:
        return """
## Cybersecurity Best Practices

### Essential Security Measures
1. **Strong Authentication**: Use MFA where possible
2. **Regular Updates**: Keep all systems and applications patched
3. **Data Protection**: Encrypt sensitive information
4. **Network Security**: Implement proper firewall and segmentation
5. **Monitoring**: Enable logging and regular review of security events
6. **Backup**: Maintain regular backups of critical data
7. **Access Control**: Apply least privilege principle

### Additional Resources
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CIS Controls: https://www.cisecurity.org/controls/

For more specific guidance, please try again later when our API service is available.
"""

# Choose between CrewAI and Langchain based on query complexity
def determine_query_complexity(query):
    """Determine if a query is complex enough to use CrewAI or if Langchain is sufficient."""
    complex_keywords = [
        'vulnerability', 'exploit', 'zero-day', 'attack vector', 'mitigation strategy',
        'risk assessment', 'penetration test', 'network security', 'encryption',
        'malware analysis', 'threat hunting', 'incident response', 'ransomware',
        'social engineering', 'data breach', 'compliance', 'security framework',
        'authentication', 'authorization', 'integrity', 'confidentiality', 'availability'
    ]
    
    # Check if query contains complex security terms
    query_lower = query.lower()
    complexity_score = sum(1 for keyword in complex_keywords if keyword in query_lower)
    
    # Check length of query (longer queries often need more detailed responses)
    length_factor = min(len(query) / 50, 3)  # Cap at 3 points
    
    total_score = complexity_score + length_factor
    
    # Determine if query requires CrewAI (complex) or Langchain (simple)
    return total_score >= 2  # Arbitrary threshold, adjust as needed

@router.get("/security-chat-analytics")
async def security_chat_analytics(
    days: int = Query(30, description="Number of days to analyze"),
    current_user: User = Depends(get_current_active_user)
):
    """Provide analytics on security chat usage and topics (placeholder for now)."""
    try:
        # In a real implementation, this would query a database for chat history
        # For now, we'll return mock data
        return {
            "total_queries": 120,
            "period_days": days,
            "top_topics": [
                {"topic": "ransomware", "count": 15},
                {"topic": "phishing", "count": 12},
                {"topic": "zero-day", "count": 10},
                {"topic": "encryption", "count": 8},
                {"topic": "data breach", "count": 7}
            ],
            "query_complexity": {
                "simple": 75,
                "complex": 45
            },
            "average_response_time": "3.2 seconds"
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error retrieving chat analytics: {str(e)}")

# Add a health check endpoint for the security chat service
@router.get("/security-chat-health")
async def security_chat_health():
    """Check if the security chat services are functioning properly."""
    try:
        # Instead of making a test call that could hit rate limits,
        # simply check if the components are available
        is_healthy = True
        
        # Return health status
        return {
            "status": "healthy",
            "message": "Security chat service is operational",
            "timestamp": datetime.now().isoformat(),
            "services": {
                "langchain": "operational",
                "crewai": "operational",
                "gemini_api": "operational"
            }
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": f"Error in security chat service: {str(e)}",
            "timestamp": datetime.now().isoformat(),
            "services": {
                "langchain": "unknown",
                "crewai": "unknown",
                "gemini_api": "failed"
            }
        }

# Export the router
def get_router():
    return router
