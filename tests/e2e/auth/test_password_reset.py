"""
Tests for the password reset flow.
"""

from playwright.sync_api import Page

from tests.e2e.pages.password_reset_page import PasswordResetPage
from tests.e2e.pages.login_page import LoginPage
from tests.e2e.helpers.database_helpers import get_user_by_username

import time
import pytest 

def test_password_reset_flow(page: Page, flask_server: dict, test_user):
    """Test the complete password reset flow."""
    reset_page = PasswordResetPage(page, flask_server["base_url"])
    reset_page.navigate()

    # Step 1: Request reset code
    reset_page.request_reset_code(test_user.username, test_user.email)

    # Wait for redirect to verification code entry step
    page.wait_for_url("**/password-reset/codesent=true", timeout=10000)

    # Step 2: Submit verification code (123456 set by E2E_TESTING=1) and new password
    new_password = "NewStrongPassword123!"
    reset_page.submit_new_password(test_user.username, "123456", new_password)

    # Wait for redirect back to login upon success
    page.wait_for_url("**/login/redirect=*", timeout=10000)

    # Verify login works with the new password
    login_page = LoginPage(page, flask_server["base_url"])
    login_page.login(test_user.username, new_password)

    # Should redirect to home successfully
    page.wait_for_url("**/", timeout=10000)

@pytest.mark.auth
def test_wrong_reset_code_keeps_password_unchanged(
    flask_server, test_user, db_path
):
    """Test that an incorrect reset code does not change the user's password."""
    from app import app

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    user_before = get_user_by_username(str(db_path), test_user.username)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["password_reset_code"] = "123456"
            session["password_reset_username"] = test_user.username
            session["password_reset_timestamp"] = time.time()
            session["password_reset_attempts"] = 0

        response = client.post(
            "/password-reset/codesent=true",
            data={
                "username": test_user.username,
                "code": "999999",
                "password": "NewPassword123!",
                "password_confirm": "NewPassword123!",
            },
        )

        assert response.status_code == 200

        with client.session_transaction() as session:
            assert session["password_reset_attempts"] == 1

    user_after = get_user_by_username(str(db_path), test_user.username)
    assert user_after["password"] == user_before["password"]

@pytest.mark.auth
def test_expired_reset_code_keeps_password_unchanged(
    flask_server, test_user, db_path
):
    """Test that an expired reset code does not change the user's password."""
    from app import app

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    user_before = get_user_by_username(str(db_path), test_user.username)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["password_reset_code"] = "123456"
            session["password_reset_username"] = test_user.username
            session["password_reset_timestamp"] = time.time() - 901
            session["password_reset_attempts"] = 0

        response = client.post(
            "/password-reset/codesent=true",
            data={
                "username": test_user.username,
                "code": "123456",
                "password": "NewPassword123!",
                "password_confirm": "NewPassword123!",
            },
        )

        assert response.status_code == 302
        assert response.headers["Location"].endswith(
            "/password-reset/codesent=false"
        )

        with client.session_transaction() as session:
            assert "password_reset_code" not in session
            assert "password_reset_username" not in session
            assert "password_reset_timestamp" not in session
            assert "password_reset_attempts" not in session

    user_after = get_user_by_username(str(db_path), test_user.username)
    assert user_after["password"] == user_before["password"]

@pytest.mark.auth
def test_fifth_failed_reset_attempt_triggers_lockout(
    flask_server, test_user, db_path
):
    """Test that five failed password-reset attempts trigger lockout."""
    from app import app

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    user_before = get_user_by_username(str(db_path), test_user.username)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["password_reset_code"] = "123456"
            session["password_reset_username"] = test_user.username
            session["password_reset_timestamp"] = time.time()
            session["password_reset_attempts"] = 4

        response = client.post(
            "/password-reset/codesent=true",
            data={
                "username": test_user.username,
                "code": "999999",
                "password": "NewPassword123!",
                "password_confirm": "NewPassword123!",
            },
        )

        assert response.status_code == 200

        with client.session_transaction() as session:
            assert session["password_reset_attempts"] == 0
            assert session["password_reset_lockout_until"] > time.time()
            assert "password_reset_code" not in session
            assert "password_reset_username" not in session
            assert "password_reset_timestamp" not in session

    user_after = get_user_by_username(str(db_path), test_user.username)
    assert user_after["password"] == user_before["password"]

@pytest.mark.auth
def test_locked_out_user_cannot_reset_password(
    flask_server, test_user, db_path
):
    """Test that a locked-out user cannot reset their password."""
    from app import app

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    user_before = get_user_by_username(str(db_path), test_user.username)

    with app.test_client() as client:
        with client.session_transaction() as session:
            session["password_reset_code"] = "123456"
            session["password_reset_username"] = test_user.username
            session["password_reset_timestamp"] = time.time()
            session["password_reset_attempts"] = 0
            session["password_reset_lockout_until"] = time.time() + 900

        response = client.post(
            "/password-reset/codesent=true",
            data={
                "username": test_user.username,
                "code": "123456",
                "password": "NewPassword123!",
                "password_confirm": "NewPassword123!",
            },
        )

        assert response.status_code == 200

        with client.session_transaction() as session:
            assert session["password_reset_lockout_until"] > time.time()

    user_after = get_user_by_username(str(db_path), test_user.username)
    assert user_after["password"] == user_before["password"]