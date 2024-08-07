import falcon
from falcon.testing import create_environ
import logging
import pytest
from regps.app import fastapi_app
import sys
import time
import threading
import requests


# Create a logger object.
logger = logging.getLogger(__name__)

# Configure the logger to write messages to stdout.
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

# Set the log level to include all messages.
logger.setLevel(logging.DEBUG)


@pytest.fixture(scope="session")
def start_server():
    # Wrap the FastAPI app with WSGIMiddleware
    def run_server():
        fastapi_app.main()

    # Start the server in a separate thread
    server_thread = threading.Thread(target=run_server)
    server_thread.start()
    # Give it some time to start up
    time.sleep(3)
    yield
    # Stop Gunicorn server after tests have finished
    server.shutdown()
    server_thread.join()


def test_service_integration(start_server):
    logger.info("Running test_local so that you can debug the server")
    # Make a request to the FastAPI server
    response = requests.get("http://0.0.0.0:8000/docs")
    
    # Assert that the response status code is 200
    assert response.status_code == 200, f"Expected status code 200, but got {response.status_code}"
        
    while(True):
        time.sleep(1)


# TODO use this test as a basis for an integration test (rather than simulated unit test)
# currently needs a pre-loaded vlei-verifier populated per signify-ts vlei-verifier test
@pytest.mark.manual
def test_ends_integration(start_server):
    # AID and SAID should be the same as what is in credential.cesr for the ECR credential
    # see https://trustoverip.github.io/tswg-acdc-specification/#top-level-fields to understand the fields/values
    AID = "EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x"
    SAID = "EElnd1DKvcDzzh7u7jBjsg2X9WgdQQuhgiu80i2VR-gk"

    # got these from signify-ts integration test
    headers = {
        "HOST": "localhost:7676",
        "CONNECTION": "keep-alive",
        "METHOD": "POST",
        "SIGNATURE": 'indexed="?0";signify="0BBbeeBw3lVmQWYBpcFH9KmRXZocrqLH_LZL4aqg5W9-NMdXqIYJ-Sao7colSTJOuYllMXFfggoMhkfpTKnvPhUF"',
        "SIGNATURE-INPUT": 'signify=("@method" "@path" "signify-resource" "signify-timestamp");created=1714854033;keyid="BPoZo2b3r--lPBpURvEDyjyDkS65xBEpmpQhHQvrwlBE";alg="ed25519"',
        "SIGNIFY-RESOURCE": "EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x",
        "SIGNIFY-TIMESTAMP": "2024-05-04T20:20:33.730000+00:00",
        "ACCEPT": "*/*",
        "ACCEPT-LANGUAGE": "*",
        "SEC-FETCH-MODE": "cors",
        "USER-AGENT": "node",
        "ACCEPT-ENCODING": "gzip, deflate",
    }

    app = service.falcon_app()
    client = falcon.testing.TestClient(app)

    result = client.simulate_get(f"/ping", headers=headers)
    assert result.status == falcon.HTTP_200
    assert result.text == "Pong"

    # result = client.simulate_get(f"/checklogin/{AID}", headers=headers)
    # assert result.status == falcon.HTTP_200

    with open(f"./data/credential.cesr", "r") as cfile:
        vlei_ecr = cfile.read()
        headers["Content-Type"] = "application/json+cesr"
        result = client.simulate_post(
            f"/login", json={"said": SAID, "vlei": vlei_ecr}, headers=headers
        )
        assert result.status == falcon.HTTP_202

    result = client.simulate_get(f"/checklogin/{AID}", headers=headers)
    assert result.status == falcon.HTTP_200

    result = client.simulate_get(f"/status/{AID}", headers=headers)
    assert (
        result.status == falcon.HTTP_401
    )  # fail because this signature should not verify
