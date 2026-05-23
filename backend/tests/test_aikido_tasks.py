from app.tasks.aikido_tasks import trigger_aikido_full_sync


def test_trigger_aikido_full_sync_enqueues_vat_sync_queue(monkeypatch):
    calls = []

    def fake_apply_async(*, args, queue, countdown):
        calls.append({"args": args, "queue": queue, "countdown": countdown})

    monkeypatch.setattr(
        "app.tasks.aikido_tasks.run_aikido_full_sync.apply_async",
        fake_apply_async,
    )

    trigger_aikido_full_sync("source-1", countdown=3)

    assert calls == [
        {"args": ["source-1"], "queue": "vat-sync", "countdown": 3},
    ]
