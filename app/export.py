"""Экспорт агрегированного состояния нод в источники (поле «Экспорт: URL приёма» у источника).

Раз в интервал плановой проверки каждому источнику с заданным URL уходит снимок всех его нод.
Связанная нода попадает в экспорт каждого источника, к которому привязана (со своим external_id).
"""

import time

from . import alerts, db

last = {}  # source_id → последняя запись лога отправки


def payload(source):
    rows = db.q(
        "SELECT sn.external_id, sn.name, sn.address, n.id AS node_id, COALESCE(ns.color, 'grey') AS state, "
        "ns.up_count, ns.down_count, ns.incident_id, ns.updated_at "
        "FROM source_nodes sn JOIN nodes n ON n.id = sn.node_id LEFT JOIN node_state ns ON ns.node_id = n.id "
        "WHERE sn.source_id=? ORDER BY sn.id",
        (source["id"],),
    )
    return {
        "source": source["name"],
        "source_type": source["type"],
        "ts": int(time.time()),
        "nodes": [
            {
                "external_id": r["external_id"],
                "node_id": r["node_id"],
                "name": r["name"],
                "address": r["address"],
                "state": r["state"],  # green | orange | red | grey
                "checkers_up": r["up_count"] or 0,
                "checkers_down": r["down_count"] or 0,
                "incident_id": r["incident_id"],
                "checked_at": r["updated_at"],
            }
            for r in rows
        ],
    }


def export_all():
    for s in db.q("SELECT * FROM sources WHERE export_url != '' ORDER BY id"):
        s = dict(s)
        alerts.post_json(s["export_url"], s["export_token"], payload(s), "export", s["name"])
        last[s["id"]] = alerts.log[0]
