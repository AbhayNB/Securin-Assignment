import pytest
from app import app, db, CVE

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

@pytest.fixture
def init_db():
    db.create_all()
    yield db
    db.drop_all()

def test_get_cves(client, init_db):
    # Insert test data into the database
    cve = CVE(id="CVE-2023-12345", source_identifier="12345", 
              published="2023-01-01T00:00:00Z", 
              last_modified="2023-01-02T00:00:00Z", 
              vuln_status="ACTIVE", description="Test CVE", 
              base_score_v2=7.5, base_score_v3=8.0)
    db.session.add(cve)
    db.session.commit()

    # Test the API endpoint
    response = client.get('/api/cves')
    assert response.status_code == 200
    assert 'CVE-2023-12345' in response.data.decode()

def test_get_cve_by_id(client, init_db):
    cve = CVE(id="CVE-2023-12345", source_identifier="12345", 
              published="2023-01-01T00:00:00Z", 
              last_modified="2023-01-02T00:00:00Z", 
              vuln_status="ACTIVE", description="Test CVE", 
              base_score_v2=7.5, base_score_v3=8.0)
    db.session.add(cve)
    db.session.commit()

    # Test the API endpoint for a specific CVE by ID
    response = client.get('/api/cves/CVE-2023-12345')
    assert response.status_code == 200
    assert 'Test CVE' in response.data.decode()
