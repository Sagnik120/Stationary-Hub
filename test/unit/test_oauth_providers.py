import pytest
import time
import security


def test_generate_oauth_state():
    """Verifies OAuth state tokens are generated with expected length and uniqueness."""
    state1 = security.generate_oauth_state("google")
    state2 = security.generate_oauth_state("github")
    assert isinstance(state1, str)
    assert len(state1) >= 16
    assert state1 != state2


def test_verify_oauth_state_success():
    """Verifies that a valid state is verified and consumed upon single use."""
    state = security.generate_oauth_state("github")
    # First verification must succeed
    assert security.verify_and_consume_oauth_state(state, "github") is True
    # Second verification must fail (single-use consumption prevents replay)
    assert security.verify_and_consume_oauth_state(state, "github") is False


def test_verify_oauth_state_mismatched_provider():
    """Verifies that state tokens issued for one provider cannot be used for another."""
    state = security.generate_oauth_state("google")
    assert security.verify_and_consume_oauth_state(state, "facebook") is False


def test_verify_oauth_state_expired():
    """Verifies that an expired state token is rejected."""
    # Issue state with 0 TTL
    state = security.generate_oauth_state("google", ttl_seconds=-1)
    assert security.verify_and_consume_oauth_state(state, "google") is False
