"""
Cloud Security Posture Dashboard - Streamlit visualization layer.

Reads the findings.json produced by main.py and renders:
  - Summary metrics (High/Medium/Low counts, total findings, scan time)
  - Filterable findings table (by severity, by service)
  - A bar chart of findings by severity and by service
  - Full description + remediation detail for each finding

Run with:
    streamlit run dashboard.py
"""
import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st

FINDINGS_PATH = Path(__file__).parent / "findings.json"

st.set_page_config(
    page_title="Cloud Security Posture Dashboard",
    page_icon=":shield:",
    layout="wide",
)


@st.cache_data
def load_findings(path: Path, mtime: float):
    with open(path) as f:
        return json.load(f)


def main():
    st.title(":shield: Cloud Security Posture Dashboard")
    st.caption("AWS security scan results for S3, EC2, and IAM")

    if not FINDINGS_PATH.exists():
        st.error(
            f"Could not find `findings.json` in this folder. "
            f"Run `python3 main.py --profile <your-profile> --region <region>` first."
        )
        return

    mtime = os.path.getmtime(FINDINGS_PATH)
    report = load_findings(FINDINGS_PATH, mtime)

    findings = report.get("findings", [])
    summary = report.get("summary", {"High": 0, "Medium": 0, "Low": 0})

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Findings", report.get("total_findings", len(findings)))
    col2.metric("High", summary.get("High", 0))
    col3.metric("Medium", summary.get("Medium", 0))
    col4.metric("Low", summary.get("Low", 0))

    st.caption(
        f"Last scan: {report.get('scan_time', 'unknown')} — "
        f"Region: {report.get('region', 'unknown')}"
    )

    if not findings:
        st.success("No findings. Either your account is clean, or nothing has been scanned yet.")
        return

    df = pd.DataFrame(findings)

    st.divider()

    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        severity_filter = st.multiselect(
            "Filter by severity",
            options=["High", "Medium", "Low"],
            default=["High", "Medium", "Low"],
        )
    with filter_col2:
        service_options = sorted(df["service"].unique().tolist())
        service_filter = st.multiselect(
            "Filter by service",
            options=service_options,
            default=service_options,
        )

    filtered_df = df[
        df["severity"].isin(severity_filter) & df["service"].isin(service_filter)
    ]

    st.divider()

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        st.subheader("Findings by Severity")
        severity_counts = filtered_df["severity"].value_counts().reindex(
            ["High", "Medium", "Low"]
        ).fillna(0)
        st.bar_chart(severity_counts)

    with chart_col2:
        st.subheader("Findings by Service")
        service_counts = filtered_df["service"].value_counts()
        st.bar_chart(service_counts)

    st.divider()

    st.subheader(f"Findings ({len(filtered_df)})")

    if filtered_df.empty:
        st.info("No findings match the current filters.")
    else:
        display_df = filtered_df[
            ["severity", "service", "resource_id", "check_name", "description"]
        ].sort_values(
            by="severity", key=lambda col: col.map({"High": 0, "Medium": 1, "Low": 2})
        )
        st.dataframe(display_df, use_container_width=True, hide_index=True)

        st.divider()
        st.subheader("Finding Details")
        for _, row in filtered_df.iterrows():
            with st.expander(f"[{row['severity']}] {row['check_name']} — {row['resource_id']}"):
                st.write(f"**Service:** {row['service']}")
                st.write(f"**Description:** {row['description']}")
                st.write(f"**Remediation:** {row['remediation']}")
                st.write(f"**Region:** {row.get('region', 'n/a')}")


if __name__ == "__main__":
    main()
