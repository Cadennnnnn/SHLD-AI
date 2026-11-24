import pytest

from shld.tools.event_tools import _validate_select


def test_allows_read_only_select_from_events():
    _validate_select(
        "SELECT event_id, severity FROM security_events WHERE severity = 'high'"
    )


@pytest.mark.parametrize(
    "query",
    [
        "DELETE FROM security_events",
        "SELECT * FROM users",
        "SELECT * FROM security_events; DROP TABLE security_events",
        "SELECT * FROM security_events -- comment",
        "SELECT * FROM security_events UNION SELECT * FROM users",
        "PRAGMA table_info(security_events)",
    ],
)
def test_rejects_unsafe_or_out_of_scope_sql(query):
    with pytest.raises(ValueError):
        _validate_select(query)
