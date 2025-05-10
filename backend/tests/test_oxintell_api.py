import pytest
import sys
import os
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, ANY

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the FastAPI app
from app import app

# Create a test client
client = TestClient(app)

# Test data
mock_user = {
    "username": "testuser",
    "email": "test@example.com",
    "role": "admin"
}

# Create fixtures for common mocks
@pytest.fixture
def mock_get_current_active_user():
    with patch("main.get_current_active_user", return_value=mock_user):
        yield

# Test cases for OxInteLL endpoints
class TestOxIntellAPI:
    
    # Test domain analysis
    @patch("routes.oxintell.get_whois_info")
    @patch("routes.oxintell.get_domain_ip")
    @patch("routes.oxintell.scan_ports")
    def test_analyze_domain(self, mock_scan_ports, mock_get_domain_ip, mock_get_whois_info, mock_get_current_active_user):
        # Setup mocks
        mock_get_whois_info.return_value = {
            "domain_name": "example.com",
            "registrar": "Example Registrar",
            "creation_date": "2000-01-01",
            "expiration_date": "2030-01-01"
        }
        
        mock_get_domain_ip.return_value = {
            "A_Records": ["93.184.216.34"],
            "AAAA_Records": ["2606:2800:220:1:248:1893:25c8:1946"]
        }
        
        mock_scan_ports.return_value = {
            "open_ports": [80, 443],
            "details": {
                "80": {"service": "HTTP", "state": "open"},
                "443": {"service": "HTTPS", "state": "open"}
            }
        }
        
        # Make request
        response = client.post(
            "/api/oxintell/domain-analysis",
            json={"domain": "example.com"}
        )
        
        # Check response
        assert response.status_code == 200
        data = response.json()
        
        # Verify that all the mocked functions were called
        mock_get_whois_info.assert_called_once_with("example.com")
        mock_get_domain_ip.assert_called_once_with("example.com")
        mock_scan_ports.assert_called_once()
        
        # Check that the response contains expected data
        assert "whois_info" in data
        assert "ip_info" in data
        assert data["whois_info"]["domain_name"] == "example.com"
        assert "93.184.216.34" in data["ip_info"]["A_Records"]
    
    # Test scheduled scans
    @patch("routes.oxintell.datetime")
    def test_schedule_security_scan(self, mock_datetime, mock_get_current_active_user):
        # Setup mock
        mock_now = datetime(2025, 5, 10, 12, 0, 0)
        mock_datetime.now.return_value = mock_now
        mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)
        
        # Make request
        response = client.post(
            "/api/oxintell/schedule-scan",
            json={
                "scan_type": "domain",
                "target": "example.com",
                "frequency": "daily",
                "notify_email": "admin@example.com",
                "parameters": {"comprehensive": True}
            }
        )
        
        # Check response
        assert response.status_code == 200
        data = response.json()
        
        # Verify response data
        assert "scan_id" in data
        assert data["scan_type"] == "domain"
        assert data["target"] == "example.com"
        assert data["frequency"] == "daily"
        assert "next_scan_time" in data
        assert data["status"] == "scheduled"
    
    # Test get scheduled scans
    def test_list_scheduled_scans(self, mock_get_current_active_user):
        # First schedule a scan
        client.post(
            "/api/oxintell/schedule-scan",
            json={
                "scan_type": "domain",
                "target": "example.com",
                "frequency": "daily"
            }
        )
        
        # Get scheduled scans
        response = client.get("/api/oxintell/scheduled-scans")
        
        # Check response
        assert response.status_code == 200
        data = response.json()
        
        # Verify that the response is a list
        assert isinstance(data, list)
        
        # Check that it contains our scheduled scan
        assert len(data) > 0
        assert any(scan["target"] == "example.com" for scan in data)
    
    # Test run immediate scan
    @patch("routes.oxintell.analyze_domain_security")
    def test_run_immediate_scan_domain(self, mock_analyze_domain, mock_get_current_active_user):
        # Setup mock
        mock_analyze_domain.return_value = {
            "security_score": 85,
            "vulnerabilities": [],
            "recommendations": []
        }
        
        # Make request for domain scan
        response = client.post(
            "/api/oxintell/immediate-scan",
            json={
                "scan_type": "domain",
                "target": "example.com",
                "parameters": {"comprehensive": True}
            }
        )
        
        # Check response
        assert response.status_code == 200
        data = response.json()
        
        # Verify mock was called
        mock_analyze_domain.assert_called_once_with("example.com", ANY)
        
        # Check response data
        assert "scan_id" in data
        assert "results" in data
        assert data["status"] == "completed"
        assert data["scan_type"] == "domain"
        assert data["target"] == "example.com"
    
    # Test get scan history
    def test_get_scan_history(self, mock_get_current_active_user):
        # First run an immediate scan
        client.post(
            "/api/oxintell/immediate-scan",
            json={
                "scan_type": "domain",
                "target": "example.com"
            }
        )
        
        # Get scan history
        response = client.get("/api/oxintell/scan-history")
        
        # Check response
        assert response.status_code == 200
        data = response.json()
        
        # Verify that the response is a list
        assert isinstance(data, list)
        
        # Check that it contains our scan
        assert len(data) > 0
        assert any(scan["target"] == "example.com" for scan in data)
        
    # Test get recent CVEs
    @patch("routes.oxintell.requests.get")
    def test_get_recent_cves(self, mock_requests_get, mock_get_current_active_user):
        # Setup mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "result": {
                "CVE_Items": [
                    {
                        "cve": {
                            "CVE_data_meta": {
                                "ID": "CVE-2023-1234"
                            },
                            "description": {
                                "description_data": [
                                    {
                                        "value": "Buffer overflow vulnerability in Example Software."
                                    }
                                ]
                            }
                        },
                        "publishedDate": "2023-01-15T10:00:00Z",
                        "impact": {
                            "baseMetricV3": {
                                "cvssV3": {
                                    "baseScore": 7.5,
                                    "baseSeverity": "HIGH"
                                }
                            }
                        }
                    }
                ]
            }
        }
        mock_requests_get.return_value = mock_response
        
        # Make request
        response = client.get("/api/oxintell/recent-cves")
        
        # Check response
        assert response.status_code == 200
        data = response.json()
        
        # Verify that the mock was called correctly
        mock_requests_get.assert_called_once()
        
        # Check that the response data is correctly processed
        assert isinstance(data, list)
        assert len(data) > 0
        assert data[0]["id"] == "CVE-2023-1234"
        assert data[0]["severity"] == "HIGH"
        assert data[0]["score"] == 7.5
