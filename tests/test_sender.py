from mrma.core.sender import SendPolicy, send_with_policy_outcome


class Response:
    def __init__(self, status_code: int):
        self.status_code = status_code


def test_retry_attempts_and_final_response_are_preserved(monkeypatch):
    calls = 0
    monkeypatch.setattr("mrma.core.sender.time.sleep", lambda _seconds: None)

    def send():
        nonlocal calls
        calls += 1
        return Response(503 if calls < 3 else 200)

    outcome = send_with_policy_outcome(send, SendPolicy(retries=2))

    assert outcome.succeeded is True
    assert outcome.attempts == 3
    assert outcome.response.status_code == 200


def test_retry_attempts_and_final_exception_are_preserved(monkeypatch):
    calls = 0
    monkeypatch.setattr("mrma.core.sender.time.sleep", lambda _seconds: None)

    def send():
        nonlocal calls
        calls += 1
        raise ConnectionResetError("reset")

    outcome = send_with_policy_outcome(send, SendPolicy(retries=1))

    assert outcome.succeeded is False
    assert outcome.attempts == 2
    assert isinstance(outcome.error, ConnectionResetError)
