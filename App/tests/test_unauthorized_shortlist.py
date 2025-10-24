
# App/tests/test_unauthorized_shortlist.py

import pytest
from App.main import create_app
from App.database import db, create_db

@pytest.fixture
def client():
    app = create_app(overrides={
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "JWT_COOKIE_SECURE": False,  # disable HTTPS for testing
    })
    with app.app_context():
        create_db()
        db.session.commit()
    with app.test_client() as client:
        yield client

# Unauthorized access tests
def test_unauthorized_shortlist_access(client):
    """
    Test that accessing the shortlist API without JWT is blocked.
    """
    # GET request to list all shortlists without JWT
    response = client.get('/api/shortlists/')
    assert response.status_code in [401, 422]

    # POST request to create shortlist without JWT
    response = client.post('/api/shortlists/', json={
        "staff_id": 1,
        "student_id": 1,
        "position_id": 1
    })
    assert response.status_code in [401, 422]

    # PUT request to update shortlist without JWT
    response = client.put('/api/shortlists/1', json={"status": "Accepted"})
    assert response.status_code in [401, 422]

    # DELETE request to delete shortlist without JWT
    response = client.delete('/api/shortlists/1')
    assert response.status_code in [401, 422]
