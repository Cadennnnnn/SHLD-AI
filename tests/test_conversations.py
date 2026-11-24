from shld.database import conversations


def test_conversation_registry_persists_and_updates_title(tmp_path, monkeypatch):
    monkeypatch.setattr(conversations, "DB_PATH", tmp_path / "conversations.sqlite")
    thread_id = conversations.create_conversation()
    conversations.touch_conversation(thread_id, "Investigate INC-TEST-001")
    conversations.touch_conversation(thread_id)

    records = conversations.list_conversations()
    match = next(row for row in records if row["thread_id"] == thread_id)
    assert match["title"] == "Investigate INC-TEST-001"
    assert match["updated_at"]
