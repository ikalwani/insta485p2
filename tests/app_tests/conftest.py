"""
Shared test fixtures.

Pytest will automatically run the client_setup_teardown() function before a
test.  A test should use "client" as an input, because the name of the fixture
is "client".

EXAMPLE:
>>> def test_simple(client):
>>>     response = client.get("/")
>>>     assert response.status_code == 200

Pytest docs:
https://docs.pytest.org/en/latest/fixture.html#conftest-py-sharing-fixture-functions
"""
import subprocess
import pytest
import insta485


def pytest_addoption(parser):
    """Add a custom command line option to skip user authentication."""
    parser.addoption(
        "--noauth",
        action="store_true",
        default=False,
        help="Skip user login."
    )


@pytest.fixture
def noauth(request):
    """Return value of --noauth command line flag."""
    return request.config.getoption('--noauth')


@pytest.fixture(name="client")
def client_setup_teardown():
    """
    Start a Flask test server with a clean database.

    Flask docs: https://flask.palletsprojects.com/en/1.1.x/testing/#testing
    """
    # Reset the database
    subprocess.run(["bin/insta485db", "reset"], check=True)

    # Configure Flask test server
    insta485.app.config["TESTING"] = True

    # Transfer control to test.  The code before the "yield" statement is setup
    # code, which is executed before the test.  Code after the "yield" is
    # teardown code, which is executed at the end of the test.  Teardown code
    # is executed whether the test passed or failed.
    with insta485.app.test_client() as client:
        yield client

    # Reset the database. After running any test any of the changes made
    # to the database should be undone.
    subprocess.run(["bin/insta485db", "reset"], check=True)
