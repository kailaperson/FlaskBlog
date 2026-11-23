"""
Tests for the user verification flow.
"""

import pytest
from playwright.sync_api import Page
import time

from tests.e2e.pages.verify_user_page import VerifyUserPage
from tests.e2e.pages.login_page import LoginPage
from tests.e2e.helpers.database_helpers import get_user_by_username


@pytest.mark.auth
def test_verify_user_flow(
    page: Page, flask_server: dict, unverified_test_user, db_path
):
    """Test the complete verify user email flow."""

    # Login as unverified user first since verify-user is login_required
    login_page = LoginPage(page, flask_server["base_url"])
    login_page.navigate()
    login_page.login(unverified_test_user.username, unverified_test_user.password)
    page.wait_for_url("**/", timeout=10000)

    verify_page = VerifyUserPage(page, flask_server["base_url"])
    verify_page.navigate()

    # Step 1: Request verification code email
    verify_page.request_verification_code()

    # Wait for redirect to verification code entry step
    page.wait_for_url("**/verify-user/codesent=true", timeout=10000)

    # Step 2: Submit verification code (123456 set by E2E_TESTING=1)
    verify_page.submit_verification_code("123456")

    # Wait for redirect back to home upon success
    page.wait_for_url("**/", timeout=10000)

    # Verify that the user state is updated in the database
    user_in_db = get_user_by_username(str(db_path), unverified_test_user.username)
    assert user_in_db["is_verified"] == "True"

@pytest.mark.auth
def test_wrong_verification_code_keeps_user_unverified(
    flask_server, unverified_test_user, db_path
):
    """Test that an incorrect verification code does not verify the user."""
    from app import app

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["username"] = unverified_test_user.username
            session["verification_code"] = "123456"
            session["verification_code_timestamp"] = time.time()
            session["verify_user_attempts"] = 0

        response = client.post(
            "/verify-user/codesent=true",
            data={"code": "999999"},
        )

        assert response.status_code == 200

        with client.session_transaction() as session:
            assert session["verify_user_attempts"] == 1

    user_in_db = get_user_by_username(
        str(db_path), unverified_test_user.username
    )
    assert user_in_db["is_verified"] == "False"

@pytest.mark.auth
def test_expired_verification_code_is_rejected(
    flask_server, unverified_test_user, db_path
):
    """Test that an expired verification code does not verify the user."""
    from app import app

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["username"] = unverified_test_user.username
            session["verification_code"] = "123456"
            session["verification_code_timestamp"] = time.time() - 901
            session["verify_user_attempts"] = 0

        response = client.post(
            "/verify-user/codesent=true",
            data={"code": "123456"},
        )

        assert response.status_code == 302
        assert response.headers["Location"].endswith(
            "/verify-user/codesent=false"
        )

        with client.session_transaction() as session:
            assert "verification_code" not in session
            assert "verification_code_timestamp" not in session
            assert "verify_user_attempts" not in session

    user_in_db = get_user_by_username(
        str(db_path), unverified_test_user.username
    )
    assert user_in_db["is_verified"] == "False"

@pytest.mark.auth
def test_locked_out_user_cannot_verify(
    flask_server, unverified_test_user, db_path
):
    """Test that a locked-out user cannot verify during the lockout period."""
    from app import app

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["username"] = unverified_test_user.username
            session["verification_code"] = "123456"
            session["verification_code_timestamp"] = time.time()
            session["verify_user_attempts"] = 0
            session["verify_user_lockout_until"] = time.time() + 900

        response = client.post(
            "/verify-user/codesent=true",
            data={"code": "123456"},
        )

        assert response.status_code == 200

        with client.session_transaction() as session:
            assert session["verify_user_lockout_until"] > time.time()

    user_in_db = get_user_by_username(
        str(db_path), unverified_test_user.username
    )
    assert user_in_db["is_verified"] == "False"

@pytest.mark.auth
def test_fifth_failed_verification_attempt_triggers_lockout(
    flask_server, unverified_test_user, db_path
):
    """Test that five failed verification attempts trigger lockout."""
    from app import app

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["username"] = unverified_test_user.username
            session["verification_code"] = "123456"
            session["verification_code_timestamp"] = time.time()
            session["verify_user_attempts"] = 4

        response = client.post(
            "/verify-user/codesent=true",
            data={"code": "999999"},
        )

        assert response.status_code == 200

        with client.session_transaction() as session:
            assert session["verify_user_attempts"] == 0
            assert session["verify_user_lockout_until"] > time.time()
            assert "verification_code" not in session
            assert "verification_code_timestamp" not in session

    user_in_db = get_user_by_username(
        str(db_path), unverified_test_user.username
    )
    assert user_in_db["is_verified"] == "False"