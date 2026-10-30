"""Optional Streamlit view of a Blindspot case."""

from __future__ import annotations

import os
from pathlib import Path

from blindspot.config import load_config
from blindspot.db import Database
from blindspot.report.export import case_payload


def main() -> None:
    import streamlit as st

    config = load_config(os.environ.get("BLINDSPOT_CONFIG", "blindspot.yaml"))
    db = Database(config.database_path())
    try:
        engagement_id = db.ensure_engagement(config.engagement, config.program, config.authorization)
        payload = case_payload(db, engagement_id)
    finally:
        db.close()
    engagement = payload["engagement"]
    st.set_page_config(page_title=f"Blindspot {engagement['name']}", layout="wide")
    st.title(engagement["name"])
    st.caption(engagement["program"])
    st.write(engagement["authorization"])
    st.write("Review prompts are leads for manual testing, not confirmed findings.")
    columns = st.columns(4)
    for index, key in enumerate(("assets", "endpoints", "changes", "queued")):
        columns[index].metric(key, payload["summary"].get(key, 0))
    st.subheader("Assets")
    st.dataframe(payload["assets"], use_container_width=True)
    st.subheader("Functionality")
    st.dataframe(payload["endpoints"], use_container_width=True)
    st.subheader("Queue")
    st.dataframe(payload["hypotheses"], use_container_width=True)
    st.subheader("Changes")
    st.dataframe(payload["changes"], use_container_width=True)


if __name__ == "__main__":
    main()


def app_path() -> Path:
    return Path(__file__).resolve()
