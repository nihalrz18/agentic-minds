"""Streamlit front end: watch the agent think.

The central requirement here is not a form and a result page - it is the live
decision log. While a run is in flight this app polls
``GET /run/{id}/status`` every 1.5 seconds and renders every
:class:`graph.state.DecisionEvent` the agent has emitted, with its stage,
confidence, risk and whether a heal was auto-applied. A spinner would hide
exactly the thing worth showing.

This process never imports the agent and never calls an LLM. It is an HTTP
client for the FastAPI backend, which keeps the browser automation, the model
calls and the credential custody in one place.

Credentials typed into the login expander are POSTed once to start the run and
are then cleared from ``st.session_state``. Nothing echoes them back, and the
backend never returns them in any response.
"""

from __future__ import annotations

import base64
import html
import time
from pathlib import Path
from typing import Any

import requests
import streamlit as st

try:
    from config import CONFIDENCE_AUTO_APPLY_THRESHOLD, get_settings

    _DEFAULTS = get_settings()
    DEFAULT_API = _DEFAULTS.api_base_url
    DEFAULT_TARGET = _DEFAULTS.default_target_url
except Exception:  # pragma: no cover - the UI must start even without config
    DEFAULT_API = "http://127.0.0.1:8000"
    DEFAULT_TARGET = "https://books.toscrape.com/"
    CONFIDENCE_AUTO_APPLY_THRESHOLD = 0.7

# Plain-language labels for the codes the agent reports internally. The
# report/events keep the machine-readable codes; the UI never shows them raw.
CLASS_LABEL = {
    "SCRIPT_ISSUE": "Test script issue (not an app bug)",
    "GENUINE_DEFECT": "Confirmed application defect",
    "ENVIRONMENT": "Environment blocker (captcha / network / login wall)",
    "UNKNOWN": "Unclear — needs a human look",
}
ACTION_LABEL = {
    "apply_patch_and_rerun": "Auto-fixed the test and re-ran it",
    "route_to_bug_packager": "Filed as a bug",
    "quarantine_environment": "Paused for a human — looks like an environment issue",
    "queue_for_review": "Sent to human review",
}

POLL_SECONDS = 1.5
REQUEST_TIMEOUT = 20

STAGES = [
    "planner",
    "coverage_gate",
    "risk_ranking",
    "generator",
    "runner",
    "healer",
    "visual_diff",
    "bug_packager",
    "report",
]

STAGE_BRIEFS = {
    "planner": "Maps the application and proposes meaningful user journeys.",
    "coverage_gate": "Checks that the plan covers critical happy, edge, and error paths.",
    "risk_ranking": "Orders flows by likely customer and business impact.",
    "generator": "Creates executable Playwright tests using live, verified selectors.",
    "runner": "Runs the generated browser tests and collects failure evidence.",
    "healer": "Separates test fragility from product defects and safely repairs scripts.",
    "visual_diff": "Compares screenshots with baselines to find interface regressions.",
    "bug_packager": "Turns confirmed defects into repro-ready engineering tickets.",
    "report": "Produces the final risk-ranked report and downloadable artifacts.",
}

STAGE_NAMES = {
    "planner": "Planner",
    "coverage_gate": "Coverage Gate",
    "risk_ranking": "Risk Ranking",
    "generator": "Generator",
    "runner": "Runner",
    "healer": "Healer",
    "visual_diff": "Visual Diff",
    "bug_packager": "Bug Packager",
    "report": "Report",
}

EVENT_ICON = {
    "start": "▶️",
    "progress": "·",
    "decision": "🧠",
    "replan": "🔁",
    "escalate": "🚨",
    "complete": "✅",
    "error": "❌",
}

# Session-state keys owned by the login widgets. They are wiped by
# clear_credential_state(), which must run *before* those widgets are
# instantiated on a given rerun: Streamlit raises StreamlitAPIException on any
# assignment to a key a live widget owns.
#
# NOTE: use comments, not bare string literals, for annotations in this file.
# Streamlit's "magic" renders a bare expression at module level as page content,
# so a docstring-style constant annotation would show up in the UI.
CRED_KEYS = ("cred_username", "cred_password", "cred_token", "cred_login_url")

RISK_ICON = {"high": "🔴", "medium": "🟠", "low": "🟢"}
STATUS_ICON = {
    "passed": "✅",
    "healed": "🩹",
    "failed": "❌",
    "error": "💥",
    "skipped": "⏭️",
}

st.set_page_config(
    page_title="Agentic Minds · Autonomous QA",
    page_icon="✦",
    layout="wide",
    initial_sidebar_state="collapsed",
)


def inject_styles(theme: str = "dark") -> None:
    """Give the app an editorial product UI instead of Streamlit defaults with dark/light theming."""
    is_light = theme == "light"

    if is_light:
        paper = "#f8f9fc"
        card = "#ffffff"
        card_raised = "#f1f3f9"
        line = "#e2e6f0"
        ink = "#0f172a"
        heading_color = "#0f172a"
        muted = "#64748b"
        text_p = "#334155"
        caption_color = "#64748b"
        violet = "#6366f1"
        violet_bright = "#4f46e5"
        violet_wash = "rgba(99, 102, 241, 0.08)"
        danger = "#ef4444"
        input_bg = "#ffffff"
        input_border = "#cbd5e1"
        btn_bg = "#f1f5f9"
        btn_border = "#cbd5e1"
        btn_text = "#1e293b"
        btn_hover_bg = "#e2e8f0"
        topbar_bg = "linear-gradient(180deg, #ffffff 0%, #f4f6fb 100%)"
        topbar_border = "#e2e6f0"
        brand_title_grad = "linear-gradient(110deg, #0f172a 15%, #4338ca 60%, #0284c7 100%)"
        badge_bg = "rgba(99, 102, 241, 0.08)"
        badge_border = "rgba(99, 102, 241, 0.25)"
        badge_text = "#4338ca"
        hero_bg = "radial-gradient(circle at 80% 20%, rgba(99,102,241,.12), transparent 24%), linear-gradient(145deg, #ffffff, #f1f4fb 70%)"
        hero_border = "#e2e6f0"
        hero_h1_grad = "linear-gradient(100deg, #0f172a, #4338ca)"
        hero_p_color = "#475569"
        shadow_alpha = "0.08"
        form_shadow_rgb = "99, 102, 241"
        stage_pending_bg = "#f8fafc"
        stage_pending_border = "#e2e6f0"
        stage_pending_text = "#64748b"
        stage_pending_name = "#475569"
        log_event_bg = "#ffffff"
        log_event_border = "#e2e6f0"
        log_summary_color = "#0f172a"
        log_detail_bg = "#f8fafc"
        log_detail_border = "#cbd5e1"
        log_detail_color = "#475569"
    else:
        paper = "#08090d"
        card = "#111218"
        card_raised = "#171821"
        line = "#242536"
        ink = "#f7f5ff"
        heading_color = "#ffffff"
        muted = "#a5a3b7"
        text_p = "#d2d0e0"
        caption_color = "#9d9bb0"
        violet = "#9b87ff"
        violet_bright = "#b8a9ff"
        violet_wash = "rgba(155, 135, 255, .13)"
        danger = "#ff7d86"
        input_bg = "#14151d"
        input_border = "#353648"
        btn_bg = "#191a25"
        btn_border = "#323447"
        btn_text = "#e2e0f0"
        btn_hover_bg = "rgba(155, 135, 255, 0.18)"
        topbar_bg = "linear-gradient(180deg, #13141d 0%, #0c0d13 100%)"
        topbar_border = "#242536"
        brand_title_grad = "linear-gradient(110deg, #ffffff 15%, #d1c7ff 60%, #67e8f9 100%)"
        badge_bg = "rgba(155, 135, 255, 0.09)"
        badge_border = "rgba(155, 135, 255, 0.3)"
        badge_text = "#c7b8ff"
        hero_bg = "radial-gradient(circle at 80% 20%, rgba(155,135,255,.24), transparent 24%), linear-gradient(145deg, #101116, #090a0e 70%)"
        hero_border = "#2a2b38"
        hero_h1_grad = "linear-gradient(100deg, #ffffff, #c7b8ff)"
        hero_p_color = "#c4c2d4"
        shadow_alpha = "0.45"
        form_shadow_rgb = "155, 135, 255"
        stage_pending_bg = "#0f1015"
        stage_pending_border = "#20212b"
        stage_pending_text = "#88869c"
        stage_pending_name = "#9593a8"
        log_event_bg = "#13141d"
        log_event_border = "#232432"
        log_summary_color = "#eae8f4"
        log_detail_bg = "#0c0d13"
        log_detail_border = "#36374a"
        log_detail_color = "#a9a6bd"

    st.markdown(
        f"""
        <style>
        @import url('https://fonts.googleapis.com/css2?family=DM+Mono:ital,wght@0,400;0,500;1,400&family=Manrope:wght@400;500;600;700;800&display=swap');

        :root {{
          --font-sans: 'Manrope', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
          --font-mono: 'DM Mono', 'SF Mono', ui-monospace, Menlo, Monaco, Consolas, monospace;
          --ink: {ink};
          --muted: {muted};
          --paper: {paper};
          --card: {card};
          --card-raised: {card_raised};
          --line: {line};
          --violet: {violet};
          --violet-bright: {violet_bright};
          --violet-wash: {violet_wash};
          --danger: {danger};
        }}
        html, body, .stApp {{
          background: var(--paper);
          color: var(--ink);
          font-family: var(--font-sans) !important;
          -webkit-font-smoothing: antialiased;
        }}
        .block-container {{ max-width: 1440px; padding: 2.2rem 4.4rem 4rem; }}

        /* Unified, proportionate headings */
        h1, h2, h3, h4, h5, h6 {{
          color: {heading_color} !important;
          font-family: var(--font-sans) !important;
          letter-spacing: -0.025em !important;
        }}
        h1 {{
          font-size: clamp(2rem, 3.2vw, 2.65rem) !important;
          font-weight: 800 !important;
          line-height: 1.15 !important;
        }}
        h2 {{
          font-size: 1.5rem !important;
          font-weight: 750 !important;
          line-height: 1.25 !important;
          margin-top: 1.2rem !important;
          margin-bottom: .45rem !important;
        }}
        h3 {{
          font-size: 1.22rem !important;
          font-weight: 700 !important;
          line-height: 1.3 !important;
          margin-top: 1rem !important;
          margin-bottom: .35rem !important;
        }}
        h4 {{
          font-size: 1.05rem !important;
          font-weight: 600 !important;
          line-height: 1.35 !important;
        }}
        p {{
          color: {text_p} !important;
          font-size: .95rem !important;
          line-height: 1.55 !important;
        }}
        .stCaption, [data-testid="stCaptionContainer"] p {{
          color: {caption_color} !important;
          font-size: .84rem !important;
          line-height: 1.5 !important;
        }}

        [data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"] {{ display: none !important; }}

        /* Topbar and Theme Switcher Row */
        [data-testid="stHorizontalBlock"]:has(.topbar-brand) {{
          align-items: center;
          border-bottom: 1px solid var(--line);
          margin: 0 0 1.5rem !important;
          max-width: 100% !important;
          padding: 0 0 0.85rem;
          width: 100%;
        }}
        [data-testid="stHorizontalBlock"]:has(.topbar-brand) > div:last-child {{
          display: flex !important;
          justify-content: flex-end !important;
        }}
        [data-testid="stHorizontalBlock"]:has(.topbar-brand) > div:last-child [data-testid="stToggle"] {{
          margin-left: auto !important;
        }}
        .topbar {{
          align-items: center;
          background: transparent !important;
          border-bottom: none !important;
          box-shadow: none !important;
          display: flex;
          justify-content: flex-start;
          margin: 0 !important;
          min-height: unset !important;
          padding: 0 !important;
          gap: 1.5rem;
          flex-wrap: wrap;
        }}
        .topbar-brand {{
          align-items: center;
          display: flex;
          gap: 1.1rem;
          line-height: 1;
        }}
        .brand-logo-wrap {{
          align-items: center;
          background: #000000;
          border: 1.5px solid rgba(155, 135, 255, 0.4);
          border-radius: 14px;
          box-shadow: 0 4px 18px rgba(0, 0, 0, 0.4), 0 0 16px rgba(155, 135, 255, 0.25);
          display: flex;
          height: 52px;
          justify-content: center;
          overflow: hidden;
          padding: 0;
          width: 52px;
          flex-shrink: 0;
        }}
        .brand-logo-img {{
          border-radius: 12px;
          display: block;
          height: 100%;
          object-fit: cover;
          width: 100%;
        }}
        .brand-text {{
          display: flex;
          flex-direction: column;
          gap: 0.22rem;
        }}
        .brand-title {{
          background: {brand_title_grad};
          -webkit-background-clip: text;
          -webkit-text-fill-color: transparent;
          font-family: var(--font-sans) !important;
          font-size: 1.35rem;
          font-weight: 850;
          letter-spacing: -0.015em;
          line-height: 1.1;
        }}
        .brand-subtitle {{
          color: var(--muted);
          font-family: var(--font-mono) !important;
          font-size: 0.72rem;
          font-weight: 600;
          letter-spacing: 0.08em;
          text-transform: uppercase;
        }}

        /* Dark / Light Mode Toggle */
        [data-testid="stToggle"] {{
          align-items: center;
          background: var(--card);
          border: 1px solid var(--line);
          border-radius: 999px;
          box-shadow: 0 2px 10px rgba(0, 0, 0, {shadow_alpha});
          display: inline-flex;
          float: right;
          margin: 0;
          padding: 0.35rem 0.95rem;
          transition: all 0.2s ease;
        }}
        [data-testid="stToggle"]:hover {{
          border-color: var(--violet);
          box-shadow: 0 0 12px rgba(155, 135, 255, 0.25);
        }}
        [data-testid="stToggle"] label p {{
          color: var(--ink) !important;
          font-family: var(--font-sans) !important;
          font-size: 0.92rem !important;
          font-weight: 700 !important;
        }}

        .aivor-eyebrow {{ color: var(--violet-bright); font-family: var(--font-mono) !important; font-size: .74rem; font-weight: 600; letter-spacing: .12em; text-transform: uppercase; }}
        .aivor-hero {{ background: {hero_bg}; border: 1.5px solid {hero_border}; border-radius: 20px; color: var(--ink); margin: 0 auto 1.6rem; max-width: 920px; overflow: hidden; padding: 2.3rem 2.6rem; position: relative; animation: hero-enter .65s cubic-bezier(.2,.8,.2,1) both; box-shadow: 0 12px 36px rgba(0, 0, 0, {shadow_alpha}); }}
        .aivor-hero:after {{ background: radial-gradient(circle, rgba(155, 135, 255, 0.32) 0%, rgba(99, 102, 241, 0.16) 45%, transparent 72%); border-radius: 50%; content: ''; filter: blur(36px); height: 340px; opacity: .75; position: absolute; right: -50px; top: -70px; width: 340px; animation: hero-ambient 7s ease-in-out infinite alternate; pointer-events: none; }}
        @keyframes hero-ambient {{ 0% {{ transform: scale(0.92); opacity: .55; }} 100% {{ transform: scale(1.08); opacity: .82; }} }}
        .aivor-hero > * {{ max-width: 640px; position: relative; z-index: 2; }}
        .aivor-hero h1 {{ background: {hero_h1_grad}; -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-family: var(--font-sans) !important; font-size: 2.35rem !important; font-weight: 800 !important; letter-spacing: -0.03em !important; line-height: 1.18 !important; margin: .55rem 0 .75rem; }}
        .aivor-hero p {{ color: {hero_p_color} !important; font-size: 1.02rem !important; line-height: 1.6 !important; max-width: 620px; }}

        /* Form Wrapper & Glowing Border Animation */
        .form-header-wrap {{
          max-width: 920px;
          margin: 0 auto 1rem;
        }}
        [data-testid="stForm"], [data-testid="stVerticalBlockBorderWrapper"] {{
          background: var(--card);
          border: 1.5px solid var(--line) !important;
          border-radius: 20px;
          box-shadow: 0 16px 44px rgba(0, 0, 0, {shadow_alpha});
        }}
        [data-testid="stForm"] {{
          max-width: 920px;
          margin: 0 auto 2.2rem;
          padding: 2.2rem 2.5rem 1.8rem;
          position: relative;
          animation: form-border-glow 6s ease-in-out infinite alternate;
        }}
        @keyframes form-border-glow {{
          0% {{
            border-color: rgba(155, 135, 255, 0.35) !important;
            box-shadow: 0 14px 40px rgba(0,0,0,{shadow_alpha}), 0 0 18px rgba({form_shadow_rgb}, 0.14);
          }}
          50% {{
            border-color: rgba(99, 102, 241, 0.5) !important;
            box-shadow: 0 18px 48px rgba(0,0,0,{shadow_alpha}), 0 0 28px rgba(99, 102, 241, 0.22);
          }}
          100% {{
            border-color: rgba(6, 182, 212, 0.4) !important;
            box-shadow: 0 14px 40px rgba(0,0,0,{shadow_alpha}), 0 0 20px rgba(6, 182, 212, 0.16);
          }}
        }}

        /* Medium Typography across Form Controls */
        label, [data-testid="stWidgetLabel"] p {{
          color: var(--ink) !important;
          font-family: var(--font-sans) !important;
          font-size: 1.02rem !important;
          font-weight: 700 !important;
          letter-spacing: -0.01em !important;
          margin-bottom: 0.35rem !important;
        }}
        .stTextInput input, .stTextArea textarea {{
          background: {input_bg} !important;
          border: 1.5px solid {input_border} !important;
          border-radius: 12px !important;
          color: var(--ink) !important;
          font-family: var(--font-sans) !important;
          font-size: 1.02rem !important;
          line-height: 1.5 !important;
          padding: 0.75rem 1rem !important;
          transition: border-color .2s ease, box-shadow .2s ease, background .2s ease;
        }}
        .stTextInput input::placeholder, .stTextArea textarea::placeholder {{
          color: var(--muted) !important;
          font-size: 1rem !important;
        }}
        .stTextInput input:focus, .stTextArea textarea:focus {{
          border-color: var(--violet) !important;
          box-shadow: 0 0 0 3px rgba(155, 135, 255, 0.28) !important;
        }}
        [data-testid="stFileUploaderDropzone"] {{
          background: {input_bg} !important;
          border: 1.5px dashed {input_border} !important;
          border-radius: 14px !important;
          padding: 1.25rem !important;
        }}
        [data-testid="stFileUploaderDropzone"] [data-testid="stFileUploaderDropzoneInstructions"] {{
          color: var(--text-p) !important;
          font-size: 1.02rem !important;
        }}
        [data-testid="stForm"] div[data-testid="stExpander"], .stExpander {{
          background: var(--card) !important;
          border: 1px solid var(--line) !important;
          border-radius: 14px !important;
        }}
        .stExpander summary p {{
          color: var(--ink) !important;
          font-size: 1.02rem !important;
          font-weight: 600 !important;
        }}

        /* Primary Form CTA Submit Button */
        [data-testid="stFormSubmitButton"] button,
        .stFormSubmitButton button,
        button[kind="primaryFormSubmit"],
        [data-testid="baseButton-primaryFormSubmit"],
        [data-testid="stForm"] .stButton button {{
          background: linear-gradient(135deg, #7c3aed 0%, #6366f1 50%, #06b6d4 100%) !important;
          border: none !important;
          border-radius: 12px !important;
          color: #ffffff !important;
          cursor: pointer !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          font-family: var(--font-sans) !important;
          font-size: 1.06rem !important;
          font-weight: 800 !important;
          letter-spacing: 0.02em !important;
          min-height: 3.2rem !important;
          padding: 0.8rem 1.6rem !important;
          box-shadow: 0 6px 24px rgba(124, 58, 237, 0.45), 0 0 16px rgba(99, 102, 241, 0.25) !important;
          transition: all .22s cubic-bezier(0.2, 0.8, 0.2, 1) !important;
          width: 100% !important;
        }}
        [data-testid="stFormSubmitButton"] button:hover,
        .stFormSubmitButton button:hover,
        button[kind="primaryFormSubmit"]:hover,
        [data-testid="stForm"] .stButton button:hover {{
          background: linear-gradient(135deg, #6d28d9 0%, #4f46e5 50%, #0891b2 100%) !important;
          box-shadow: 0 10px 32px rgba(6, 182, 212, 0.52), 0 0 22px rgba(124, 58, 237, 0.4) !important;
          transform: translateY(-2px) scale(1.006) !important;
          color: #ffffff !important;
        }}
        [data-testid="stFormSubmitButton"] button p,
        .stFormSubmitButton button p,
        button[kind="primaryFormSubmit"] p,
        [data-testid="stForm"] .stButton button p {{
          color: #ffffff !important;
          font-family: var(--font-sans) !important;
          font-size: 1.06rem !important;
          font-weight: 800 !important;
        }}

        /* Secondary / Utility Buttons (History Open, etc.) */
        .stButton button, .stDownloadButton button {{
          background: {btn_bg} !important;
          border: 1px solid {btn_border} !important;
          border-radius: 10px !important;
          color: {btn_text} !important;
          font-family: var(--font-sans) !important;
          font-size: 0.94rem !important;
          font-weight: 700 !important;
          min-height: 2.45rem !important;
          transition: all .2s ease !important;
        }}
        .stButton button:hover, .stDownloadButton button:hover {{
          background: {btn_hover_bg} !important;
          border-color: var(--violet) !important;
          color: var(--ink) !important;
          box-shadow: 0 4px 18px rgba(155, 135, 255, 0.22) !important;
          transform: translateY(-1px) !important;
        }}

        /* Align Recent Runs container with the form max-width */
        .element-container:has(div.stExpander) {{
          max-width: 880px;
          margin-left: auto !important;
          margin-right: auto !important;
        }}

        .run-heading {{ align-items: center; display: flex; flex-wrap: wrap; gap: .75rem; margin: 0; }}
        .run-heading h2 {{ color: {heading_color} !important; font-family: var(--font-sans) !important; font-size: 1.55rem !important; font-weight: 800 !important; letter-spacing: -0.02em !important; line-height: 1.2 !important; margin: 0; }}
        .target-url {{ background: rgba(155, 135, 255, .12); border: 1px solid rgba(155, 135, 255, .32); border-radius: 8px; color: var(--ink); font-family: var(--font-mono) !important; font-size: 1.05rem; font-weight: 600; padding: .24rem .68rem; word-break: break-all; }}
        .run-id-subtle {{ color: var(--muted); font-family: var(--font-mono) !important; font-size: .75rem; letter-spacing: .03em; }}
        .run-pill {{ border-radius: 999px; font-family: var(--font-mono) !important; font-size: .68rem; font-weight: 700; letter-spacing: .06em; padding: .25rem .6rem; text-transform: uppercase; }}
        .run-pill.running {{ background: rgba(234, 179, 8, 0.18); border: 1px solid rgba(234, 179, 8, 0.5); color: #fde047; }}
        .run-pill.completed {{ background: rgba(34, 197, 94, 0.18); border: 1px solid rgba(34, 197, 94, 0.5); color: #4ade80; }}
        .run-pill.failed, .run-pill.cancelled {{ background: rgba(239, 68, 68, 0.2); border: 1px solid rgba(239, 68, 68, 0.5); color: #ffb8bf; }}
        .run-pill.queued {{ background: rgba(155, 135, 255, 0.2); border: 1px solid rgba(155, 135, 255, 0.4); color: #b8a9ff; }}

        /* Smooth scrolling and anchor offsets */
        html, body, [data-testid="stAppViewContainer"] {{ scroll-behavior: smooth !important; }}
        .stage-section-anchor {{ display: block; height: 0; margin: 0; padding: 0; position: relative; top: -85px; visibility: hidden; }}
        [id^="stage-"], .stage-section-anchor {{ scroll-margin-top: 90px; }}

        /* Stage Rail Header with Quick Views */
        .stage-rail-header {{
          align-items: center;
          display: flex;
          justify-content: space-between;
          margin: 0.65rem 0 0.35rem;
          width: 100%;
        }}
        .stage-rail-title {{
          color: var(--muted);
          font-family: var(--font-mono) !important;
          font-size: 0.72rem;
          font-weight: 600;
          letter-spacing: 0.08em;
          text-transform: uppercase;
        }}
        .stage-rail-nav {{
          align-items: center;
          display: flex;
          gap: 0.45rem;
        }}
        .stage-quick-tab {{
          align-items: center;
          background: var(--card);
          border: 1px solid var(--line);
          border-radius: 6px;
          color: var(--muted) !important;
          cursor: pointer;
          display: inline-flex;
          font-family: var(--font-sans) !important;
          font-size: 0.74rem;
          font-weight: 650;
          gap: 0.3rem;
          padding: 0.22rem 0.6rem;
          text-decoration: none !important;
          transition: all 0.15s ease;
        }}
        .stage-quick-tab:hover {{
          background: var(--card-raised);
          border-color: var(--violet);
          color: var(--ink) !important;
        }}
        .stage-quick-tab.active {{
          background: rgba(99, 102, 241, 0.16);
          border-color: var(--violet-bright) !important;
          color: var(--ink) !important;
          font-weight: 750;
        }}

        /* Responsive, non-overflowing pipeline stage rail */
        .stage-rail {{
          align-items: center;
          background: transparent;
          display: flex;
          gap: 0.35rem;
          margin: 0.35rem 0 0.85rem;
          padding: 0.2rem 0 0.45rem;
          width: 100%;
          overflow-x: auto;
          scrollbar-width: thin;
        }}
        .stage-node {{
          align-items: stretch;
          background: linear-gradient(165deg, var(--card-raised) 0%, var(--card) 100%);
          border: 1px solid var(--line);
          border-radius: 10px;
          box-shadow: 0 2px 8px rgba(0, 0, 0, {shadow_alpha});
          color: var(--muted);
          cursor: pointer;
          display: flex;
          flex: 1 1 0;
          min-width: 82px;
          max-width: 140px;
          flex-direction: column;
          gap: 0.35rem;
          justify-content: space-between;
          min-height: 56px;
          padding: 0.5rem 0.6rem;
          position: relative;
          text-decoration: none !important;
          transition: all 0.18s cubic-bezier(0.2, 0.8, 0.2, 1);
          overflow: hidden;
        }}
        .stage-node:hover {{
          border-color: var(--violet);
          box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35);
          text-decoration: none !important;
          transform: translateY(-1px);
        }}
        a.stage-node {{ color: inherit !important; cursor: pointer !important; text-decoration: none !important; }}
        a.stage-node:hover, a.stage-node:focus, a.stage-node:active, a.stage-node:visited {{ color: inherit !important; text-decoration: none !important; }}
        .stage-node-top {{ align-items: center; display: flex; justify-content: space-between; width: 100%; gap: 0.25rem; }}
        .stage-name {{ color: {ink} !important; font-family: var(--font-sans) !important; font-size: 0.78rem !important; font-weight: 700 !important; letter-spacing: -0.01em; line-height: 1.15; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; width: 100%; }}
        .stage-status-badge {{ border-radius: 4px; font-family: var(--font-mono) !important; font-size: 0.58rem; font-weight: 750; letter-spacing: 0.04em; padding: 0.1rem 0.32rem; text-transform: uppercase; white-space: nowrap; }}
        .stage-dot {{ border-radius: 50%; flex-shrink: 0; height: 8px; width: 8px; }}

        /* Active / Selected stage in rail */
        .stage-node.active {{
          border-color: var(--violet-bright) !important;
          box-shadow: 0 0 18px rgba(155, 135, 255, 0.42), 0 4px 14px rgba(0, 0, 0, 0.45) !important;
          transform: translateY(-2px);
          outline: 1.5px solid var(--violet);
        }}
        .stage-node.active .stage-name {{
          color: #ffffff !important;
        }}

        /* RUNNING State: YELLOW with animated blink */
        .stage-node.running {{
          background: linear-gradient(165deg, rgba(234, 179, 8, 0.14) 0%, var(--card) 100%);
          border: 1.5px solid #facc15;
          border-top: 1.5px solid #fde047;
          box-shadow: 0 0 16px rgba(250, 204, 21, 0.25), 0 4px 12px rgba(0, 0, 0, 0.4);
        }}
        .stage-node.running .stage-name {{ color: #ffffff !important; }}
        .stage-node.running .stage-dot {{ background: #facc15; box-shadow: 0 0 8px #facc15; animation: yellow-blink 1.2s ease-in-out infinite; }}
        .stage-node.running .stage-status-badge {{ background: rgba(234, 179, 8, 0.18); border: 1px solid rgba(234, 179, 8, 0.45); color: #fde047; }}

        /* SUCCEEDED / DONE State: GREEN */
        .stage-node.done {{
          background: linear-gradient(165deg, rgba(34, 197, 94, 0.08) 0%, var(--card) 100%);
          border: 1px solid rgba(34, 197, 94, 0.35);
          border-top: 1px solid rgba(74, 222, 128, 0.5);
          box-shadow: 0 2px 8px rgba(0, 0, 0, {shadow_alpha});
        }}
        .stage-node.done .stage-name {{ color: {ink} !important; }}
        .stage-node.done .stage-dot {{ background: #22c55e; box-shadow: 0 0 6px rgba(34, 197, 94, 0.6); }}
        .stage-node.done .stage-status-badge {{ background: rgba(34, 197, 94, 0.12); border: 1px solid rgba(34, 197, 94, 0.25); color: #4ade80; }}

        /* PENDING State: theme aware */
        .stage-node.pending {{
          background: {stage_pending_bg};
          border: 1px solid {stage_pending_border};
          opacity: 0.7;
        }}
        .stage-node.pending .stage-name {{ color: {stage_pending_name} !important; }}
        .stage-node.pending .stage-dot {{ background: {stage_pending_border}; border: 1px solid var(--line); box-shadow: none; }}
        .stage-node.pending .stage-status-badge {{ background: transparent; border: 1px solid var(--line); color: {stage_pending_text}; }}

        /* FAILED State: RED */
        .stage-node.failed {{
          background: linear-gradient(165deg, rgba(239, 68, 68, 0.14) 0%, var(--card) 100%);
          border: 1.5px solid #ef4444;
          border-top: 1.5px solid #fca5a5;
          box-shadow: 0 0 14px rgba(239, 68, 68, 0.2);
        }}
        .stage-node.failed .stage-name {{ color: #fee2e2 !important; }}
        .stage-node.failed .stage-dot {{ background: #ef4444; box-shadow: 0 0 8px rgba(239, 68, 68, 0.7); }}
        .stage-node.failed .stage-status-badge {{ background: rgba(239, 68, 68, 0.18); border: 1px solid rgba(239, 68, 68, 0.4); color: #f87171; }}

        .stage-arrow {{ align-self: center; color: var(--line); flex: 0 0 auto; font-size: 0.8rem; margin: 0; user-select: none; transition: color 0.2s ease; }}
        .stage-arrow.done {{ color: rgba(34, 197, 94, 0.65); }}
        .stage-arrow.running {{ color: rgba(250, 204, 21, 0.8); }}

        /* Action buttons aligned with product UI */
        .st-key-start_another_run button, .st-key-cancel_run button {{ border-radius: 9px !important; font-family: var(--font-sans) !important; font-size: .82rem !important; font-weight: 700 !important; letter-spacing: .01em !important; min-height: 2.3rem !important; padding: .38rem .85rem !important; transition: all .18s ease !important; }}
        .st-key-start_another_run button {{ background: {btn_bg} !important; border: 1px solid {btn_border} !important; color: {btn_text} !important; box-shadow: 0 2px 8px rgba(0, 0, 0, .2) !important; }}
        .st-key-start_another_run button:hover {{ background: {btn_hover_bg} !important; border-color: var(--violet) !important; color: var(--ink) !important; box-shadow: 0 6px 18px rgba(155, 135, 255, .22) !important; transform: translateY(-1px) !important; }}
        .st-key-cancel_run button {{ background: rgba(239, 68, 68, 0.12) !important; border: 1px solid rgba(239, 68, 68, 0.35) !important; color: #ff7d86 !important; box-shadow: 0 2px 8px rgba(0, 0, 0, .2) !important; }}
        .st-key-cancel_run button:hover:not(:disabled) {{ background: rgba(239, 68, 68, 0.22) !important; border-color: #ef4444 !important; color: #ffffff !important; box-shadow: 0 6px 18px rgba(239, 68, 68, .25) !important; transform: translateY(-1px) !important; }}
        .st-key-cancel_run button:disabled {{ background: var(--card) !important; border-color: var(--line) !important; color: var(--muted) !important; cursor: not-allowed !important; opacity: .5 !important; transform: none !important; box-shadow: none !important; }}

        /* Edge round corner design for metric cards */
        .metrics-grid, .metrics-ribbon {{
          display: grid;
          grid-template-columns: repeat(5, 1fr);
          gap: 0.75rem;
          margin: 0.65rem 0 1.25rem;
          width: 100%;
        }}
        .metric-card, .metric-item {{
          background: linear-gradient(145deg, var(--card-raised), var(--card));
          border: 1px solid var(--line);
          border-radius: 14px;
          box-shadow: 0 4px 16px rgba(0, 0, 0, {shadow_alpha});
          display: flex;
          flex-direction: column;
          gap: 0.45rem;
          min-height: 74px;
          padding: 0.85rem 1.1rem;
          transition: border-color 0.2s ease, transform 0.2s ease;
        }}
        .metric-card:hover, .metric-item:hover {{
          border-color: rgba(155, 135, 255, 0.4);
          transform: translateY(-1px);
        }}
        .metric-divider {{ display: none !important; }}
        .metric-card .m-lbl, .metric-item .m-lbl {{
          color: var(--muted);
          font-family: var(--font-mono) !important;
          font-size: 0.7rem;
          font-weight: 700;
          letter-spacing: 0.08em;
          text-transform: uppercase;
        }}
        .metric-card .m-val, .metric-item .m-val {{
          color: {heading_color};
          font-family: var(--font-sans) !important;
          font-size: 1.38rem;
          font-weight: 800;
          letter-spacing: -0.02em;
          line-height: 1.2;
        }}
        .metric-card.m-passed .m-val, .metric-item.m-passed .m-val {{ color: #22c55e !important; }}
        .metric-card.m-failed .m-val, .metric-item.m-failed .m-val {{ color: #ef4444 !important; }}
        .metric-card.m-healed .m-val, .metric-item.m-healed .m-val {{ color: #a855f7 !important; }}

        /* Metric compaction fallback helper */
        [data-testid="stMetric"] {{ background: linear-gradient(145deg, var(--card-raised), var(--card)); border: 1px solid var(--line); border-radius: 11px; min-height: 64px; padding: .5rem .75rem; }}
        [data-testid="stMetricLabel"] {{ color: var(--muted) !important; font-family: var(--font-mono) !important; font-size: .66rem !important; font-weight: 600 !important; letter-spacing: .06em !important; text-transform: uppercase !important; }}
        [data-testid="stMetricValue"] {{ color: {heading_color} !important; font-family: var(--font-sans) !important; font-size: 1.28rem !important; font-weight: 800 !important; letter-spacing: -.02em !important; line-height: 1.15 !important; }}

        /* Stage Navigation Pills & Stage View Banner */
        .stage-nav-wrap {{ align-items: center; display: flex; flex-wrap: wrap; gap: .45rem; margin: .85rem 0 1.35rem; padding: .35rem 0; }}
        .stage-nav-pill {{ align-items: center; background: var(--card); border: 1px solid var(--line); border-radius: 999px; color: var(--muted); cursor: pointer; display: inline-flex; font-family: var(--font-sans) !important; font-size: .82rem; font-weight: 700; gap: .35rem; padding: .35rem .85rem; text-decoration: none !important; transition: all .2s ease; user-select: none; }}
        .stage-nav-pill:hover {{ background: var(--card-raised); border-color: var(--violet); color: var(--ink) !important; transform: translateY(-1px); }}
        .stage-nav-pill.active {{ background: linear-gradient(135deg, rgba(155, 135, 255, 0.22) 0%, rgba(99, 102, 241, 0.16) 100%); border-color: var(--violet-bright) !important; box-shadow: 0 0 12px rgba(155, 135, 255, 0.3); color: var(--ink) !important; font-weight: 800; }}
        .stage-view-banner {{ align-items: center; background: linear-gradient(135deg, rgba(155, 135, 255, 0.1) 0%, var(--card) 100%); border: 1px solid rgba(155, 135, 255, 0.35); border-radius: 12px; display: flex; justify-content: space-between; margin: .6rem 0 1.2rem; padding: .65rem 1.1rem; }}
        .stage-view-banner-title {{ color: var(--ink); font-family: var(--font-sans) !important; font-size: 1.05rem; font-weight: 750; }}
        .stage-view-banner-reset {{ color: var(--violet-bright) !important; font-family: var(--font-sans) !important; font-size: .84rem; font-weight: 700; text-decoration: none !important; }}
        .stage-view-banner-reset:hover {{ text-decoration: underline !important; }}
        [data-testid="stDataFrame"] {{ border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }}
        [data-testid="stAlert"] {{ border-radius: 12px; }}
        .section-kicker {{ color: var(--violet-bright) !important; font-family: var(--font-mono) !important; font-size: .74rem !important; font-weight: 600 !important; letter-spacing: .12em !important; margin-bottom: .2rem !important; text-transform: uppercase !important; }}

        /* Decision log: newest on top, distinct styling */
        .log-event {{ animation: event-in .32s ease-out both; background: {log_event_bg}; border: 1px solid {log_event_border}; border-radius: 10px; margin-bottom: .55rem; padding: .75rem .9rem; transition: border-color .18s ease, background .18s ease; }}
        .log-event:hover {{ background: {btn_hover_bg}; border-color: var(--violet); }}
        .log-event.latest {{ background: linear-gradient(135deg, rgba(155, 135, 255, 0.08) 0%, {log_event_bg} 100%); border: 1px solid rgba(155, 135, 255, 0.4); border-left: 4px solid var(--violet-bright); box-shadow: 0 0 18px rgba(155, 135, 255, 0.1); }}
        .log-event.error {{ background: linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, {log_event_bg} 100%); border: 1px solid rgba(239, 68, 68, 0.45); border-left: 4px solid #ef4444; }}
        .log-event.warning {{ background: linear-gradient(135deg, rgba(234, 179, 8, 0.1) 0%, {log_event_bg} 100%); border: 1px solid rgba(234, 179, 8, 0.45); border-left: 4px solid #facc15; }}
        .log-event-top {{ align-items: center; display: flex; justify-content: space-between; margin-bottom: .3rem; }}
        .log-stage-link {{ color: var(--violet-bright) !important; font-family: var(--font-mono) !important; font-size: .75rem; font-weight: 700; letter-spacing: .06em; text-decoration: none !important; text-transform: uppercase; transition: color .15s ease; }}
        .log-stage-link:hover {{ color: var(--ink) !important; text-decoration: underline !important; }}
        .log-badges-wrap {{ align-items: center; display: flex; flex-wrap: wrap; gap: .35rem; }}
        .log-badge-latest {{ background: rgba(155, 135, 255, 0.22); border: 1px solid var(--violet-bright); border-radius: 999px; color: var(--ink); font-family: var(--font-mono) !important; font-size: .6rem; font-weight: 700; letter-spacing: .06em; padding: .12rem .48rem; animation: mark-glow 2.5s ease-in-out infinite; }}
        .log-badge-time {{ color: var(--muted); font-family: var(--font-mono) !important; font-size: .68rem; }}
        .log-badge-pill {{ background: {btn_bg}; border: 1px solid {btn_border}; border-radius: 4px; color: var(--ink); font-family: var(--font-mono) !important; font-size: .64rem; font-weight: 600; padding: .1rem .36rem; }}
        .log-badge-pill.applied {{ background: rgba(34, 197, 94, 0.15); border-color: rgba(34, 197, 94, 0.4); color: #4ade80; }}
        .log-badge-pill.not-applied {{ background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.4); color: #ffb8bf; }}
        .log-badge-pill.review {{ background: rgba(234, 179, 8, 0.16); border-color: rgba(234, 179, 8, 0.45); color: #fde047; font-weight: 700; }}
        .log-badge-pill.risk-high {{ background: rgba(239, 68, 68, 0.18); border-color: rgba(239, 68, 68, 0.5); color: #fca5a5; }}
        .log-summary {{ color: {log_summary_color}; font-size: .95rem; line-height: 1.45; }}
        .log-detail {{ background: {log_detail_bg}; border-left: 2px solid {log_detail_border}; border-radius: 0 6px 6px 0; color: {log_detail_color}; font-family: var(--font-mono) !important; font-size: .76rem; line-height: 1.5; margin-top: .35rem; padding: .3rem .55rem; word-break: break-word; }}

        @keyframes hero-enter {{ from {{ opacity: 0; transform: translateY(16px); }} to {{ opacity: 1; transform: translateY(0); }} }}
        @keyframes orbit {{ to {{ transform: rotate(360deg); }} }} @keyframes pulse-ring {{ 50% {{ opacity: .32; transform: scale(1.08); }} }}
        @keyframes mark-glow {{ 50% {{ box-shadow: 0 0 32px rgba(155,135,255,.75); }} }} @keyframes active-ping {{ 50% {{ box-shadow: 0 0 0 7px rgba(155,135,255,.04); }} }}
        @keyframes yellow-blink {{ 0% {{ box-shadow: 0 0 0 0 rgba(250, 204, 21, 0.85), 0 0 8px #facc15; transform: scale(1); }} 50% {{ box-shadow: 0 0 0 6px rgba(250, 204, 21, 0), 0 0 16px #fde047; transform: scale(1.18); }} 100% {{ box-shadow: 0 0 0 0 rgba(250, 204, 21, 0), 0 0 8px #facc15; transform: scale(1); }} }}
        @keyframes event-in {{ from {{ opacity: 0; transform: translateX(-7px); }} to {{ opacity: 1; transform: translateX(0); }} }}

        /* Completely eliminate all Streamlit header chrome: Accessibility, Stop, Deploy, Status, Toolbar, Decoration */
        header[data-testid="stHeader"],
        [data-testid="stHeader"],
        [data-testid="stToolbar"],
        header [data-testid="stToolbar"],
        [data-testid="stToolbarActions"],
        [data-testid="stDeployButton"],
        .stDeployButton,
        [data-testid="stStatusWidget"],
        [data-testid="stDecoration"],
        #MainMenu,
        footer,
        [data-testid="stActionButton"],
        [aria-label="Accessibility"],
        [aria-label="Stop running"],
        button[title="Stop execution"],
        button[title="Stop"],
        header[data-testid="stHeader"] button,
        .stAppDeployButton {{
          display: none !important;
          visibility: hidden !important;
          opacity: 0 !important;
          pointer-events: none !important;
          height: 0 !important;
          width: 0 !important;
          margin: 0 !important;
          padding: 0 !important;
          position: fixed !important;
          top: -9999px !important;
          left: -9999px !important;
          z-index: -999 !important;
        }}
        header[data-testid="stHeader"] {{
          background: transparent !important;
          height: 0 !important;
          min-height: 0 !important;
          max-height: 0 !important;
          padding: 0 !important;
          overflow: hidden !important;
        }}

        @media (max-width: 900px) {{
          .block-container {{ padding: 1.2rem 1rem 3rem; }}
          .aivor-hero {{ padding: 2.25rem 1.7rem; }}
          .aivor-hero:after {{ right: -230px; }}
          .run-heading {{ align-items: flex-start; flex-direction: column; }}
          [data-testid="stHorizontalBlock"]:has(.topbar-brand) {{ flex-direction: column; gap: 1rem; align-items: flex-start; }}
        }}
        @media (prefers-reduced-motion: reduce) {{
          *, *:before, *:after {{ animation-duration: .01ms !important; animation-iteration-count: 1 !important; transition-duration: .01ms !important; }}
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


_current_theme = st.session_state.get("theme", "dark")
inject_styles(_current_theme)


# ==========================================================================
# HTTP helpers - every call returns (ok, payload_or_error)
# ==========================================================================
def api_get(base: str, path: str, *, timeout: int = REQUEST_TIMEOUT) -> tuple[bool, Any]:
    try:
        response = requests.get(f"{base.rstrip('/')}{path}", timeout=timeout)
    except requests.RequestException as exc:
        return False, f"could not reach the API at {base}: {type(exc).__name__}"
    if response.status_code >= 400:
        return False, _error_text(response)
    try:
        return True, response.json()
    except ValueError:
        return True, response.text


def api_get_text(base: str, path: str) -> tuple[bool, str]:
    try:
        response = requests.get(f"{base.rstrip('/')}{path}", timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return False, f"could not reach the API: {type(exc).__name__}"
    if response.status_code >= 400:
        return False, _error_text(response)
    return True, response.text


def api_post(base: str, path: str, payload: dict[str, Any]) -> tuple[bool, Any]:
    try:
        response = requests.post(
            f"{base.rstrip('/')}{path}", json=payload, timeout=REQUEST_TIMEOUT
        )
    except requests.RequestException as exc:
        return False, f"could not reach the API at {base}: {type(exc).__name__}"
    if response.status_code >= 400:
        return False, _error_text(response)
    try:
        return True, response.json()
    except ValueError:
        return False, "the API returned a non-JSON response"


def _plain_error(message: str | None, limit: int = 180) -> str:
    """First line of a Playwright error, trimmed of its verbose call log."""
    if not message:
        return ""
    first_line = message.strip().split("\n", 1)[0].strip()
    if len(first_line) > limit:
        first_line = first_line[: limit - 1].rstrip() + "…"
    return first_line


def _error_text(response: requests.Response) -> str:
    try:
        body = response.json()
        detail = body.get("detail", body)
    except ValueError:
        detail = response.text[:400]
    if isinstance(detail, list):  # pydantic validation errors
        detail = "; ".join(
            f"{'.'.join(str(p) for p in item.get('loc', []))}: {item.get('msg', '')}"
            for item in detail
        )
    return f"HTTP {response.status_code}: {detail}"


# ==========================================================================
# Sidebar
# ==========================================================================
def render_sidebar() -> str:
    st.sidebar.markdown("<div class='aivor-eyebrow'>Workspace settings</div>", unsafe_allow_html=True)
    base = st.sidebar.text_input("API base URL", value=st.session_state.get("api_base", DEFAULT_API))
    st.session_state["api_base"] = base

    if st.sidebar.button("Check connection", use_container_width=True):
        ok, payload = api_get(base, "/health", timeout=8)
        if not ok:
            st.sidebar.error(payload)
        else:
            st.session_state["health"] = payload

    health = st.session_state.get("health")
    if isinstance(health, dict):
        provider = health.get("llm_provider", "none")
        if health.get("llm_configured"):
            st.sidebar.success(f"API up · provider: **{provider}**")
        else:
            st.sidebar.error("API up, but no LLM provider is configured")
        if provider == "offline-stub":
            st.sidebar.warning(
                "LLM_OFFLINE_MODE is on. Responses come from a deterministic stub, "
                "not a model. Runs made now are for plumbing checks only."
            )
        if not health.get("playwright_ready", True):
            st.sidebar.warning(health.get("note") or "Playwright browsers are not installed.")
        models = health.get("models") or {}
        st.sidebar.caption(
            f"reasoning: `{models.get('reasoning', '?')}`\n\n"
            f"codegen: `{models.get('codegen', '?')}`"
        )
        flags = health.get("feature_flags") or {}
        with st.sidebar.expander("Feature flags"):
            for name, value in flags.items():
                st.write(f"{'✅' if value else '⬜'} `{name}`")
        st.sidebar.caption(f"Active runs: {health.get('active_runs', 0)}")

    st.sidebar.divider()
    st.sidebar.subheader("Security")
    st.sidebar.caption(
        "Use a **throwaway test account**. Credentials are held in memory for the "
        "duration of one run, are never logged, never written into a report, never "
        "embedded in a generated test, and are wiped when the run ends. Point the "
        "agent at staging - generation clicks and fills real forms."
    )
    return base


LOGO_PATH = Path(__file__).resolve().parent / "assets" / "agentic_minds_logo_opt.png"
LOGO_RAW_PATH = Path(__file__).resolve().parent / "assets" / "agentic_minds_logo.png"


def get_logo_data_uri() -> str:
    """Return base64 data URI of the Agentic Minds logo."""
    target = LOGO_PATH if LOGO_PATH.exists() else LOGO_RAW_PATH
    if target.exists():
        try:
            raw = target.read_bytes()
            b64 = base64.b64encode(raw).decode("ascii")
            return f"data:image/png;base64,{b64}"
        except Exception:
            pass
    return (
        "data:image/svg+xml;utf8,"
        "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
        "<defs><linearGradient id='g' x1='0%' y1='0%' x2='100%' y2='100%'>"
        "<stop offset='0%' stop-color='%239b87ff'/><stop offset='100%' stop-color='%2367e8f9'/>"
        "</linearGradient></defs>"
        "<rect width='100' height='100' rx='20' fill='%23111218'/>"
        "<text x='50' y='60' font-family='sans-serif' font-weight='800' font-size='36' "
        "fill='url(%23g)' text-anchor='middle'>AM</text></svg>"
    )


def render_topbar() -> None:
    """Agentic Minds branded topbar with logo, hackathon badge, and dark/light mode toggle."""
    theme = st.session_state.get("theme", "dark")
    is_light = theme == "light"
    logo_src = get_logo_data_uri()

    col_brand, col_theme = st.columns([5.5, 1.5], vertical_alignment="center")
    with col_brand:
        st.markdown(
            f"""
            <div class="topbar">
              <div class="topbar-brand" aria-label="Agentic Minds">
                <div class="brand-logo-wrap">
                  <img
                    src="{logo_src}"
                    alt="Agentic Minds Logo"
                    class="brand-logo-img"
                  />
                </div>
                <div class="brand-text">
                  <span class="brand-title">Agentic Minds</span>
                  <span class="brand-subtitle">Autonomous Test Orchestration</span>
                </div>
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_theme:
        toggled = st.toggle(
            "☀️ Light Mode" if not is_light else "🌙 Dark Mode",
            value=is_light,
            key="theme_toggle_switch",
        )
        new_theme = "light" if toggled else "dark"
        if new_theme != theme:
            st.session_state["theme"] = new_theme
            st.rerun()


def get_active_stage() -> str:
    """Retrieve currently active stage from query params or session state."""
    try:
        if hasattr(st, "query_params") and "stage" in st.query_params:
            val = str(st.query_params.get("stage") or "").lower().strip()
            if val:
                return val
    except Exception:
        pass
    return str(st.session_state.get("active_stage") or "overview").lower().strip()


def render_stage_navigation_bar(active_stage: str = "overview") -> None:
    """Interactive stage navigation bar allowing direct 1-click inspection of any stage."""
    items = [
        ("overview", "All Overview", "🔍"),
        ("planner", "Planner", "🧭"),
        ("coverage_gate", "Coverage Gate", "🛡️"),
        ("risk_ranking", "Risk Ranking", "📊"),
        ("generator", "Generator", "⚡"),
        ("runner", "Runner", "▶️"),
        ("healer", "Healer", "🩹"),
        ("visual_diff", "Visual Diff", "👁️"),
        ("bug_packager", "Bug Packager", "🐛"),
        ("report", "Report", "📄"),
        ("decision_log", "Decision Log", "📜"),
    ]
    pills = []
    for key, label, icon in items:
        cls = "stage-nav-pill active" if key == active_stage else "stage-nav-pill"
        pills.append(
            f"<a href='?stage={key}' class='{cls}' target='_self' title='View {html.escape(label)}'>{icon} {html.escape(label)}</a>"
        )
    st.markdown(
        "<div class='stage-nav-wrap'>" + "".join(pills) + "</div>",
        unsafe_allow_html=True,
    )


# ==========================================================================
# Submission form
# ==========================================================================
def render_form(base: str) -> None:
    st.markdown(
        """
        <section class="aivor-hero">
          <div class="aivor-eyebrow">Hackathon Team · Agentic Minds</div>
          <h1>Give your product<br>an agent that tests.</h1>
          <p>Engineered by <strong>Agentic Minds</strong> — maps your application, turns real user flows into browser tests, and
          returns an evidence-backed risk report while you stay focused on shipping.</p>
        </section>
        <div class="form-header-wrap">
          <div class="section-kicker">New audit</div>
          <h2>Start a test run</h2>
          <p>Choose a target and the agent will do the rest. Use staging whenever the flow can change data.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("start_run", clear_on_submit=False):
        url = st.text_input("Target URL *", value=DEFAULT_TARGET, placeholder="https://example.com")
        intent = st.text_area(
            "What should it focus on? (optional)",
            placeholder="focus on checkout and authentication flows",
            height=80,
        )
        prd_file = st.file_uploader(
            "Product requirements document (optional, .txt or .md)", type=["txt", "md"]
        )

        with st.expander("Login (optional) — only if the target needs it"):
            st.caption(
                "Sent once to start the run, then cleared from this browser session. "
                "Never echoed back, never stored, never written to disk."
            )
            col_a, col_b = st.columns(2)
            username = col_a.text_input("Username or email", key=CRED_KEYS[0])
            password = col_b.text_input("Password", type="password", key=CRED_KEYS[1])
            col_c, col_d = st.columns(2)
            token = col_c.text_input("Bearer token", type="password", key=CRED_KEYS[2])
            login_url = col_d.text_input(
                "Login URL", key=CRED_KEYS[3], placeholder="auto-detect"
            )

        submitted = st.form_submit_button("🚀 Start autonomous run", use_container_width=True)

    if not submitted:
        return

    if not url.strip():
        st.error("A target URL is required.")
        return

    prd_text = None
    if prd_file is not None:
        try:
            prd_text = prd_file.getvalue().decode("utf-8", errors="replace")
        except Exception as exc:
            st.warning(f"Could not read the uploaded PRD ({exc}); continuing without it.")

    payload: dict[str, Any] = {"url": url.strip()}
    if intent.strip():
        payload["intent"] = intent.strip()
    if prd_text:
        payload["prd_text"] = prd_text
    credentials = {
        k: v
        for k, v in {
            "username": username or None,
            "password": password or None,
            "token": token or None,
            "login_url": login_url or None,
        }.items()
        if v
    }
    if credentials:
        payload["credentials"] = credentials

    ok, response = api_post(base, "/run", payload)
    if not ok:
        st.error(response)
        return

    st.session_state["run_id"] = response.get("run_id")
    st.session_state["polling"] = True
    # The credential widgets are wiped by clear_credential_state() at the top of
    # the next run, before any widget is instantiated. Clearing them here would
    # raise StreamlitAPIException, because Streamlit forbids assigning to a
    # session_state key that a live widget owns.
    st.rerun()


# ==========================================================================
# Live view
# ==========================================================================
def render_stage_strip(
    current: str,
    status: str,
    decision_log: list[dict[str, Any]] | None = None,
    active_stage: str = "overview",
) -> None:
    if current in STAGES:
        index = STAGES.index(current)
    elif current in ("orchestrator", "start", "") and status in ("running", "queued"):
        index = 0
    else:
        index = -1

    completed_stages: set[str] = set()
    failed_stages: set[str] = set()
    if decision_log:
        for event in decision_log:
            stg = event.get("stage")
            ev = event.get("event")
            if stg:
                if ev == "complete":
                    completed_stages.add(stg)
                elif ev == "error":
                    failed_stages.add(stg)

    states: list[str] = []
    badges: list[str] = []
    for position, stage in enumerate(STAGES):
        if status == "completed":
            state = "done"
            badge = "SUCCEEDED"
        elif status in ("failed", "cancelled"):
            if stage in failed_stages or (position == index and status == "failed"):
                state = "failed"
                badge = "FAILED"
            elif position < index or stage in completed_stages:
                state = "done"
                badge = "SUCCEEDED"
            else:
                state = "pending"
                badge = "PENDING"
        else:  # running or queued
            if position == index or (current == stage and status == "running"):
                state = "running"
                badge = "RUNNING"
            elif position < index or stage in completed_stages:
                state = "done"
                badge = "SUCCEEDED"
            else:
                state = "pending"
                badge = "PENDING"
        states.append(state)
        badges.append(badge)

    header_html = (
        f"<div class='stage-rail-header'>"
        f"<span class='stage-rail-title'>Pipeline Execution Flow</span>"
        f"</div>"
    )

    chunks: list[str] = []
    for position, stage in enumerate(STAGES):
        label = STAGE_NAMES.get(stage, stage.replace("_", " ").title())
        brief = STAGE_BRIEFS.get(stage, "")
        state = states[position]
        badge = badges[position]
        is_selected = (stage == active_stage)
        active_cls = " active" if is_selected else ""
        if position > 0:
            prev_state = states[position - 1]
            arrow_cls = "stage-arrow"
            if prev_state == "done":
                arrow_cls += " done"
            elif prev_state == "running":
                arrow_cls += " running"
            chunks.append(f"<span class='{arrow_cls}'>→</span>")
        chunks.append(
            f"<a href='?stage={stage}#stage-{stage}' class='stage-node {state}{active_cls}' target='_self' title='Click to view {html.escape(label)} details · {html.escape(brief)}' onclick=\"document.getElementById('stage-{stage}')?.scrollIntoView({{behavior: 'smooth'}});\">"
            f"<div class='stage-node-top'>"
            f"<span class='stage-dot'></span>"
            f"<span class='stage-status-badge'>{badge}</span>"
            f"</div>"
            f"<div class='stage-name'>{html.escape(label)}</div>"
            f"</a>"
        )
    st.markdown(
        header_html + "<div class='stage-rail'>" + "".join(chunks) + "</div>",
        unsafe_allow_html=True,
    )


def render_metrics(payload: dict[str, Any]) -> None:
    counts = payload.get("counts") or {}
    started = payload.get("started_at") or ""
    elapsed = ""
    try:
        from datetime import datetime, timezone

        begin = datetime.fromisoformat(started)
        end = (
            datetime.fromisoformat(payload["finished_at"])
            if payload.get("finished_at")
            else datetime.now(timezone.utc)
        )
        total_sec = max(0, int((end - begin).total_seconds()))
        hours = total_sec // 3600
        mins = (total_sec % 3600) // 60
        secs = total_sec % 60
        if hours > 0:
            elapsed = f"{hours}h {mins}m {secs}s"
        elif mins > 0:
            elapsed = f"{mins}m {secs}s"
        else:
            elapsed = f"{secs}s"
    except Exception:
        elapsed = "—"

    stage_name = (payload.get("current_stage") or "—").replace("_", " ").title()
    replan_val = f"{payload.get('replan_count', 0)} / 2"
    flows_val = counts.get("flows", 0)
    tests_val = counts.get("tests_generated", 0)
    passed_val = counts.get("passed", 0)
    failed_val = counts.get("failed", 0)
    healed_val = counts.get("healed", 0)
    bugs_val = counts.get("bugs_filed", 0)
    visual_val = counts.get("visual_regressions", 0)

    st.markdown(
        f"""
        <div class='metrics-grid'>
          <div class='metric-card metric-item'><span class='m-lbl'>STAGE</span><span class='m-val'>{html.escape(stage_name)}</span></div>
          <div class='metric-card metric-item'><span class='m-lbl'>ELAPSED</span><span class='m-val'>{html.escape(elapsed)}</span></div>
          <div class='metric-card metric-item'><span class='m-lbl'>RE-PLANS</span><span class='m-val'>{html.escape(replan_val)}</span></div>
          <div class='metric-card metric-item'><span class='m-lbl'>FLOWS</span><span class='m-val'>{flows_val}</span></div>
          <div class='metric-card metric-item'><span class='m-lbl'>TESTS</span><span class='m-val'>{tests_val}</span></div>
          <div class='metric-card metric-item m-passed'><span class='m-lbl'>PASSED</span><span class='m-val'>{passed_val}</span></div>
          <div class='metric-card metric-item m-failed'><span class='m-lbl'>FAILED</span><span class='m-val'>{failed_val}</span></div>
          <div class='metric-card metric-item m-healed'><span class='m-lbl'>HEALED</span><span class='m-val'>{healed_val}</span></div>
          <div class='metric-card metric-item'><span class='m-lbl'>BUGS FILED</span><span class='m-val'>{bugs_val}</span></div>
          <div class='metric-card metric-item'><span class='m-lbl'>VISUAL REGRESSIONS</span><span class='m-val'>{visual_val}</span></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if payload.get("force_proceeded"):
        st.warning(
            "The re-plan budget was exhausted and the orchestrator force-proceeded. "
            "Remaining coverage gaps are listed in the report."
        )
    if payload.get("credentials_present"):
        login_ok = payload.get("login_ok")
        if login_ok is True:
            st.success("Authenticated — protected pages were in scope.")
        elif login_ok is False:
            st.error(
                "AUTH BLOCKED — login failed, so only publicly reachable pages were explored."
            )


def render_decision_log(events: list[dict[str, Any]]) -> None:
    st.subheader("Agent decision log")
    st.caption(
        "Newest updates appear at the top. Every stage emits an event the moment it starts, "
        "decides, and finishes. Click any stage to jump to its details."
    )
    if not events:
        st.info("Waiting for the first event…")
        return

    # Reverse events so newest update is displayed on top, older below
    reversed_events = list(reversed(events))

    with st.container(height=480):
        for idx, event in enumerate(reversed_events):
            is_latest = (idx == 0)
            icon = EVENT_ICON.get(event.get("event", ""), "·")
            raw_stage = str(event.get("stage") or "")
            stage_display = raw_stage.replace("_", " ").title()
            stage_slug = raw_stage.lower()
            summary = event.get("summary") or ""
            ev_type = str(event.get("event") or "").lower()

            badges: list[str] = []
            if is_latest:
                badges.append("<span class='log-badge-latest'>● LATEST</span>")

            ts_raw = event.get("ts") or ""
            if ts_raw:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(ts_raw)
                    time_label = dt.strftime("%H:%M:%S")
                    badges.append(f"<span class='log-badge-time'>{time_label}</span>")
                except Exception:
                    pass

            confidence = event.get("confidence")
            if confidence is not None:
                badges.append(f"<span class='log-badge-pill'>conf {float(confidence):.2f}</span>")
            risk = event.get("risk")
            if risk:
                badges.append(f"<span class='log-badge-pill risk-{risk}'>{RISK_ICON.get(risk, '')} {str(risk).upper()}</span>")
            if event.get("auto_applied") is True:
                badges.append("<span class='log-badge-pill applied'>AUTO-APPLIED</span>")
            elif event.get("auto_applied") is False:
                badges.append("<span class='log-badge-pill not-applied'>NOT APPLIED</span>")
            if event.get("needs_human_review"):
                badges.append("<span class='log-badge-pill review'>NEEDS HUMAN REVIEW</span>")

            extra_cls = ""
            if is_latest:
                extra_cls += " latest"
            if ev_type == "error":
                extra_cls += " error"
            elif ev_type in ("replan", "escalate"):
                extra_cls += " warning"

            stage_link = (
                f"<a href='?stage={stage_slug}' class='log-stage-link' target='_self' title='Jump to {html.escape(stage_display)} details'>"
                f"{html.escape(icon)} {html.escape(stage_display)}"
                f"</a>"
            )

            badge_html = " ".join(badges)
            detail = (event.get("detail") or "").strip()
            detail_html = (
                f"<div class='log-detail'>{html.escape(detail[:600])}</div>"
                if detail
                else ""
            )

            st.markdown(
                f"<div class='log-event{extra_cls}'>"
                f"<div class='log-event-top'>"
                f"<div class='log-stage'>{stage_link}</div>"
                f"<div class='log-badges-wrap'>{badge_html}</div>"
                f"</div>"
                f"<div class='log-summary'>{html.escape(summary)}</div>"
                f"{detail_html}"
                f"</div>",
                unsafe_allow_html=True,
            )


def render_run_header(base: str, run_id: str, payload: dict[str, Any]) -> None:
    status = str(payload.get("status") or "running").lower()
    target_url = payload.get("target_url") or ""
    safe_status = html.escape(status)

    verb_map = {
        "running": "Running",
        "completed": "Completed",
        "failed": "Failed",
        "queued": "Queued",
        "cancelled": "Cancelled",
    }
    verb = verb_map.get(status, "Run")
    display_title = f"{verb} for" if target_url else "Run"

    url_html = (
        f"<span class='target-url'>{html.escape(target_url)}</span>"
        if target_url
        else ""
    )
    st.markdown("<div class='aivor-eyebrow'>Autonomous run</div>", unsafe_allow_html=True)

    col_title, col_btn1, col_btn2 = st.columns([6.8, 1.7, 1.5], vertical_alignment="center")
    with col_title:
        st.markdown(
            "<div class='run-heading'>"
            f"<h2>{display_title}</h2>"
            f"{url_html}"
            f"<span class='run-pill {safe_status}'>{safe_status}</span>"
            f"<span class='run-id-subtle' style='display:none;' data-run-id='{html.escape(run_id)}'>{html.escape(run_id)}</span>"
            "</div>",
            unsafe_allow_html=True,
        )
    with col_btn1:
        if st.button("← Start another run", key="start_another_run", use_container_width=True):
            for key in ("run_id", "polling"):
                st.session_state.pop(key, None)
            if hasattr(st, "query_params"):
                st.query_params.clear()
            st.rerun()
    with col_btn2:
        can_cancel = status in ("queued", "running")
        if st.button(
            "⏹ Cancel run",
            key="cancel_run",
            disabled=not can_cancel,
            use_container_width=True,
        ):
            api_delete_ok, _ = api_get(base, f"/run/{run_id}/status")
            try:
                requests.delete(f"{base.rstrip('/')}/run/{run_id}", timeout=10)
            except requests.RequestException as exc:
                st.error(f"Could not cancel: {type(exc).__name__}")
            st.session_state["polling"] = False
            st.rerun()


def render_live_stage_details(
    current: str,
    status: str,
    events: list[dict[str, Any]],
    counts: dict[str, Any],
    active_stage: str = "overview",
) -> None:
    st.markdown("<div class='section-kicker'>Live Stage Details</div>", unsafe_allow_html=True)
    st.subheader("Stage breakdown")
    st.caption(
        "Live status and telemetry for every stage in the pipeline. "
        "Click any stage in the strip above to jump directly here."
    )

    events_by_stage: dict[str, list[dict[str, Any]]] = {}
    for ev in events:
        s = str(ev.get("stage") or "").lower()
        events_by_stage.setdefault(s, []).append(ev)

    current_idx = STAGES.index(current) if current in STAGES else (0 if current in ("orchestrator", "start", "") else -1)

    for pos, stage in enumerate(STAGES):
        label = STAGE_NAMES.get(stage, stage.replace("_", " ").title())
        brief = STAGE_BRIEFS.get(stage, "")
        st_events = events_by_stage.get(stage, [])

        if status == "completed":
            badge = "SUCCEEDED"
        elif status in ("failed", "cancelled"):
            if pos == current_idx and status == "failed":
                badge = "FAILED"
            elif pos < current_idx or any(e.get("event") == "complete" for e in st_events):
                badge = "SUCCEEDED"
            else:
                badge = "PENDING"
        else:
            if pos == current_idx:
                badge = "RUNNING"
            elif pos < current_idx or any(e.get("event") == "complete" for e in st_events):
                badge = "SUCCEEDED"
            else:
                badge = "PENDING"

        # Anchor tag for in-page smooth navigation
        st.markdown(f"<div id='stage-{stage}' class='stage-section-anchor'></div>", unsafe_allow_html=True)
        is_active = (badge in ("RUNNING", "FAILED")) or (stage == active_stage) or (stage == "planner" and not st_events)
        with st.expander(f"{label} · {badge}", expanded=is_active):
            st.caption(brief)
            if badge == "RUNNING":
                st.info(f"⏳ **{label}** is currently active and processing…")
            if st_events:
                st.markdown("**Recent stage events (latest first):**")
                for e in reversed(st_events):
                    e_icon = EVENT_ICON.get(e.get("event", ""), "·")
                    st.markdown(f"- {e_icon} **{str(e.get('event', '')).upper()}**: {e.get('summary', '')}")
                    detail = str(e.get("detail") or "").strip()
                    if detail:
                        st.caption(f"  {detail[:300]}")
            elif badge == "PENDING":
                st.caption("Waiting for prior stages to finish.")


def render_live(base: str, run_id: str, active_stage: str = "overview") -> None:
    ok, payload = api_get(base, f"/run/{run_id}/status")
    if not ok:
        st.error(payload)
        if st.button("Stop polling"):
            st.session_state["polling"] = False
        return

    status = payload.get("status", "running")
    render_run_header(base, run_id, payload)
    render_stage_strip(
        payload.get("current_stage", ""),
        status,
        payload.get("decision_log"),
        active_stage=active_stage,
    )
    render_metrics(payload)
    st.divider()

    if active_stage == "decision_log":
        render_decision_log(payload.get("decision_log") or [])
    elif active_stage in STAGES:
        render_live_stage_details(
            payload.get("current_stage", ""),
            status,
            payload.get("decision_log") or [],
            payload.get("counts") or {},
            active_stage=active_stage,
        )
    else:
        render_decision_log(payload.get("decision_log") or [])
        st.divider()
        render_live_stage_details(
            payload.get("current_stage", ""),
            status,
            payload.get("decision_log") or [],
            payload.get("counts") or {},
            active_stage=active_stage,
        )

    if status in ("completed", "failed", "cancelled"):
        st.session_state["polling"] = False
        if payload.get("error"):
            st.error(f"Run error: {payload['error']}")
        render_results(base, run_id, active_stage=active_stage)
        return

    time.sleep(POLL_SECONDS)
    st.rerun()


# ==========================================================================
# Final results
# ==========================================================================
def render_results(base: str, run_id: str, active_stage: str = "overview") -> None:
    ok, report = api_get(base, f"/run/{run_id}/report")
    if not ok:
        st.warning(f"Report not available yet — {report}")
        return

    st.divider()

    # If a specific stage is selected, show the banner
    if active_stage != "overview" and active_stage in STAGES:
        stage_name = STAGE_NAMES.get(active_stage, active_stage.replace("_", " ").title())
        st.markdown(
            f"""
            <div class='stage-view-banner'>
              <div class='stage-view-banner-title'>Viewing Stage: <strong>{html.escape(stage_name)}</strong></div>
              <a href='#stage-report' class='stage-view-banner-reset'>↑ Executive Summary</a>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<div id='stage-report' class='stage-section-anchor'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-kicker'>Run report · Executive Synthesis</div>", unsafe_allow_html=True)
    st.header("Executive Report")
    summary = report.get("executive_summary") or ""
    if summary:
        st.markdown(f"#### What happened\n{summary}")
    impact = report.get("business_impact") or ""
    if impact:
        st.success(f"**Business impact.** {impact}")

    _render_planner(report, expanded=(active_stage == "planner"))
    _render_coverage(report, expanded=(active_stage == "coverage_gate"))
    _render_flow_table(report)
    _render_generator(report, expanded=(active_stage == "generator"))
    _render_runner(report, expanded=(active_stage == "runner"))
    _render_healer(report, expanded=(active_stage == "healer"))
    _render_visual(report)
    _render_bugs(base, run_id, report)
    _render_limitations(report)
    _render_downloads(base, run_id)


def _render_planner(report: dict[str, Any], expanded: bool = False) -> None:
    st.markdown("<div id='stage-planner' class='stage-section-anchor'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-kicker'>Stage · Planner</div>", unsafe_allow_html=True)
    flows = report.get("flows") or []
    target = report.get("target_url") or "target application"
    st.subheader(f"Site exploration & requirements discovery ({len(flows)} user journeys)")
    st.caption("Discovered user journeys, crawl scope, and PRD requirement mapping.")
    if flows:
        journey_data = [
            {
                "Journey / Flow": f.get("flow_name") or f.get("flow_id"),
                "Category": str(f.get("category", "core_flow")).replace("_", " ").title(),
                "Outcome": "✅ Passed" if str(f.get("status", "")).lower() == "passed" else ("❌ Failed" if str(f.get("status", "")).lower() in ("failed", "error") else "⏳ Discovered"),
                "Flow ID": f.get("flow_id", ""),
            }
            for f in flows
        ]
        st.dataframe(journey_data, use_container_width=True, hide_index=True)
    _render_prd_and_radar(report, expanded=expanded)


def _render_generator(report: dict[str, Any], expanded: bool = False) -> None:
    st.markdown("<div id='stage-generator' class='stage-section-anchor'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-kicker'>Stage · Generator</div>", unsafe_allow_html=True)
    flows = report.get("flows") or []
    totals = report.get("totals") or {}
    test_count = totals.get("tests_generated", len(flows))
    st.subheader(f"Generated Playwright tests ({test_count} tests)")
    st.caption(
        "Synthesized resilient Playwright test suites with self-healing selector fallbacks "
        "and deterministic assertion checkpoints."
    )
    if flows:
        if expanded:
            for f in flows:
                fid = f.get("flow_id", "")
                fname = f.get("flow_name", fid)
                cat = str(f.get("category", "")).replace("_", " ")
                st.markdown(f"**{fname}** (`{cat}` · `{fid}`)")
                code = f.get("code") or ""
                if code:
                    st.code(code, language="python")
                else:
                    st.caption("Synthesized test script executed in browser sandbox.")
        else:
            with st.expander(f"View generated test flows ({len(flows)})", expanded=False):
                for f in flows:
                    fid = f.get("flow_id", "")
                    fname = f.get("flow_name", fid)
                    cat = str(f.get("category", "")).replace("_", " ")
                    st.markdown(f"**{fname}** (`{cat}` · `{fid}`)")
                    code = f.get("code") or ""
                    if code:
                        st.code(code, language="python")
                    else:
                        st.caption("Synthesized test script executed in browser sandbox.")


def _render_runner(report: dict[str, Any], expanded: bool = False) -> None:
    st.markdown("<div id='stage-runner' class='stage-section-anchor'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-kicker'>Stage · Runner</div>", unsafe_allow_html=True)
    flows = report.get("flows") or []
    totals = report.get("totals") or {}
    passed = totals.get("passed", sum(1 for f in flows if str(f.get("status", "")).lower() == "passed"))
    failed = totals.get("failed", sum(1 for f in flows if str(f.get("status", "")).lower() in ("failed", "error")))
    st.subheader(f"Test runner outcomes ({passed} passed · {failed} failed)")
    st.caption("Isolated browser execution metrics, trace records, and assertion diagnostics.")
    if flows:
        cols = st.columns(3)
        cols[0].metric("Passed", passed)
        cols[1].metric("Failed", failed)
        avg_dur = sum(float(f.get("duration_s", 0) or 0) for f in flows) / max(len(flows), 1)
        cols[2].metric("Avg flow duration", f"{avg_dur:.1f}s")
        if expanded:
            st.markdown("##### Execution breakdown")
            st.dataframe(
                [
                    {
                        "Flow": f.get("flow_name") or f.get("flow_id"),
                        "Status": "✅ Passed" if str(f.get("status", "")).lower() == "passed" else "❌ Failed",
                        "Duration": f"{float(f.get('duration_s', 0) or 0):.1f}s",
                        "Error": f.get("error") or "—",
                    }
                    for f in flows
                ],
                use_container_width=True,
                hide_index=True,
            )


def _render_healer(report: dict[str, Any], expanded: bool = False) -> None:
    st.markdown("<div id='stage-healer' class='stage-section-anchor'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-kicker'>Stage · Healer</div>", unsafe_allow_html=True)
    _render_review_queue(report)
    _render_healer_table(report, expanded=expanded)


def _render_flow_table(report: dict[str, Any]) -> None:
    st.markdown("<div id='stage-risk_ranking' class='stage-section-anchor'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-kicker'>Stage · Risk Ranking</div>", unsafe_allow_html=True)
    rows = report.get("flows") or []
    st.subheader("Risk-ranked results")
    st.caption(
        "Ordered by business risk first, then by how bad the outcome was — not by flow index."
    )
    if not rows:
        st.info("No flows were executed.")
        return
    table = [
        {
            "Risk": f"{RISK_ICON.get(str(r.get('risk')), '')} {str(r.get('risk', '')).upper()}",
            "Flow": r.get("flow_name", ""),
            "Category": str(r.get("category", "")).replace("_", " "),
            "Status": f"{STATUS_ICON.get(str(r.get('status')), '')} {r.get('status', '')}",
            "What happened": _plain_error(r.get("error_message")) or r.get("outcome_label", ""),
            "Duration": f"{float(r.get('duration_s', 0) or 0):.1f}s",
            "Bugs": ", ".join(r.get("bug_ids") or []),
        }
        for r in rows
    ]
    st.dataframe(table, use_container_width=True, hide_index=True)


def _render_coverage(report: dict[str, Any], expanded: bool = False) -> None:
    st.markdown("<div id='stage-coverage_gate' class='stage-section-anchor'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-kicker'>Stage · Coverage Gate</div>", unsafe_allow_html=True)
    evaluation = report.get("coverage_evaluation") or {}
    gaps = report.get("coverage_gaps") or []
    with st.expander(
        f"Coverage gate — score {evaluation.get('score', 0)} · "
        f"{'PASSED' if evaluation.get('passed') else 'FAILED'} · "
        f"{report.get('replan_count', 0)} re-plan(s)",
        expanded=expanded,
    ):
        checks = evaluation.get("checks") or []
        if checks:
            st.dataframe(
                [
                    {
                        "": "✅" if c.get("satisfied") else "❌",
                        "ID": c.get("id"),
                        "Requirement": c.get("requirement"),
                        "Evidence": c.get("evidence"),
                    }
                    for c in checks
                ],
                use_container_width=True,
                hide_index=True,
            )
        if evaluation.get("rationale"):
            st.caption(evaluation["rationale"])
        if gaps:
            st.warning("**Remaining coverage gaps**\n\n" + "\n".join(f"- {g}" for g in gaps))


def _render_review_queue(report: dict[str, Any]) -> None:
    queue = report.get("needs_human_review") or []
    st.subheader(f"Needs human review ({len(queue)})")
    if not queue:
        st.caption("Nothing was left for a human: every finding was confidently classified.")
        return
    st.caption(
        "These findings were **not auto-fixed**. Either the agent's confidence was below "
        f"the {CONFIDENCE_AUTO_APPLY_THRESHOLD:.0%} auto-apply bar, or the failure looks like "
        "an environment problem (captcha, network, login wall) that no code patch can solve. "
        "Each is queued here with its evidence instead of being silently changed."
    )
    for action in queue:
        with st.container(border=True):
            cols = st.columns([3, 1, 1])
            cols[0].markdown(f"**{action.get('flow_name') or action.get('flow_id')}**")
            cols[1].metric("Confidence", f"{float(action.get('confidence', 0)):.2f}")
            classification = str(action.get("classification", ""))
            cols[2].markdown(f"**{CLASS_LABEL.get(classification, classification)}**")
            st.write(action.get("rationale", ""))
            if action.get("patch_summary"):
                st.caption(action["patch_summary"])
            refs = action.get("evidence_refs") or []
            if refs:
                st.caption("Evidence: " + " · ".join(str(r) for r in refs))


def _render_healer_table(report: dict[str, Any], expanded: bool = False) -> None:
    actions = report.get("healer_actions") or []
    if not actions:
        return
    with st.expander(f"All healer actions ({len(actions)})", expanded=expanded):
        st.dataframe(
            [
                {
                    "Flow": a.get("flow_name") or a.get("flow_id"),
                    "Classification": CLASS_LABEL.get(str(a.get("classification")), a.get("classification")),
                    "Confidence": round(float(a.get("confidence", 0) or 0), 2),
                    "Auto-applied": "✅" if a.get("auto_applied") else "—",
                    "Re-run": a.get("rerun_status") or "—",
                    "What the agent did": ACTION_LABEL.get(str(a.get("action")), a.get("action")),
                }
                for a in actions
            ],
            use_container_width=True,
            hide_index=True,
        )


def _render_visual(report: dict[str, Any]) -> None:
    st.markdown("<div id='stage-visual_diff' class='stage-section-anchor'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-kicker'>Stage · Visual Diff</div>", unsafe_allow_html=True)
    findings = report.get("visual_findings") or []
    regressions = [f for f in findings if f.get("is_regression")]
    st.subheader(f"Visual regression ({len(regressions)} of {len(findings)} frames)")
    st.caption(
        "Pixel comparison against the stored baseline. Reported separately from "
        "functional failures: a flow can pass every assertion while the layout breaks."
    )
    if not findings:
        st.caption("No frames were compared.")
        return
    for finding in findings:
        if not finding.get("is_regression") and not finding.get("is_new_baseline"):
            continue
        label = (
            f"{'🔺' if finding.get('is_regression') else '🆕'} "
            f"{finding.get('flow_name') or finding.get('flow_id')} — "
            f"{float(finding.get('changed_ratio', 0)) * 100:.1f}% changed"
        )
        with st.expander(label, expanded=bool(finding.get("is_regression"))):
            st.caption(finding.get("note", ""))
            columns = st.columns(3)
            for column, key, caption in (
                (columns[0], "baseline_path", "Baseline"),
                (columns[1], "current_path", "Current"),
                (columns[2], "diff_path", "Diff"),
            ):
                path = finding.get(key)
                if path and Path(path).is_file():
                    column.image(str(path), caption=caption, use_container_width=True)
                else:
                    column.caption(f"{caption}: not available locally")


def _render_bugs(base: str, run_id: str, report: dict[str, Any]) -> None:
    st.markdown("<div id='stage-bug_packager' class='stage-section-anchor'></div>", unsafe_allow_html=True)
    st.markdown("<div class='section-kicker'>Stage · Bug Packager</div>", unsafe_allow_html=True)
    bugs = report.get("packaged_bugs") or []
    st.subheader(f"Packaged bugs ({len(bugs)})")
    if not bugs:
        st.caption("No genuine application defects were confirmed in this run.")
        return
    st.caption(
        "Each is a distinct artifact on disk: a standalone repro script, a screenshot "
        "and a paste-ready ticket. No credentials appear in any of them."
    )
    for bug in bugs:
        bug_id = bug.get("bug_id", "")
        risk = str(bug.get("risk", "medium"))
        with st.expander(
            f"{RISK_ICON.get(risk, '')} **{bug_id}** — {bug.get('title', '')} "
            f"({bug.get('severity', 'major')})"
        ):
            ok, artifact = api_get(base, f"/run/{run_id}/bugs/{bug_id}")
            if not ok:
                st.error(artifact)
                continue
            st.markdown(artifact.get("description", ""))
            shot = artifact.get("screenshot_base64")
            if shot:
                try:
                    st.image(base64.b64decode(shot), caption="Failure screenshot")
                except Exception:
                    st.caption("Screenshot could not be decoded.")
            elif artifact.get("note"):
                st.caption(artifact["note"])

            columns = st.columns(2)
            if artifact.get("repro_script"):
                columns[0].download_button(
                    "⬇ repro.py",
                    artifact["repro_script"],
                    file_name=f"{bug_id}_repro.py",
                    mime="text/x-python",
                    use_container_width=True,
                    key=f"repro_{bug_id}",
                )
            if artifact.get("ticket_markdown"):
                columns[1].download_button(
                    "⬇ ticket.md",
                    artifact["ticket_markdown"],
                    file_name=f"{bug_id}_ticket.md",
                    mime="text/markdown",
                    use_container_width=True,
                    key=f"ticket_{bug_id}",
                )
            with st.popover("View repro script"):
                st.code(artifact.get("repro_script", ""), language="python")


def _render_prd_and_radar(report: dict[str, Any], expanded: bool = False) -> None:
    gaps = report.get("prd_gaps") or []
    if gaps:
        uncovered = [g for g in gaps if not g.get("covered")]
        with st.expander(f"PRD gap analysis — {len(uncovered)} of {len(gaps)} uncovered", expanded=expanded):
            st.dataframe(
                [
                    {
                        "": "✅" if g.get("covered") else "❌",
                        "Requirement": g.get("requirement"),
                        "Best matching flow": g.get("best_match_flow") or "—",
                        "Similarity": round(float(g.get("similarity", 0) or 0), 2),
                    }
                    for g in gaps
                ],
                use_container_width=True,
                hide_index=True,
            )

    radar = report.get("regression_radar") or {}
    if radar and radar.get("enabled") is not False and not radar.get("first_run"):
        with st.expander(f"Regression radar — {radar.get('summary', '')}"):
            st.caption(
                f"Compared with run `{radar.get('compared_with') or '—'}` "
                f"({radar.get('history_runs', 0)} run(s) of history for this target)."
            )
            cols = st.columns(4)
            cols[0].metric("Newly failing", len(radar.get("newly_failing") or []))
            cols[1].metric("Newly passing", len(radar.get("newly_passing") or []))
            cols[2].metric("Flows added", len(radar.get("flows_added") or []))
            cols[3].metric("Flows removed", len(radar.get("flows_removed") or []))
            for label, items in (
                ("Newly failing", radar.get("newly_failing")),
                ("Newly passing", radar.get("newly_passing")),
                ("Flows added", radar.get("flows_added")),
                ("Flows removed", radar.get("flows_removed")),
            ):
                if items:
                    st.markdown(f"**{label}:** " + ", ".join(str(i) for i in items))


def _render_limitations(report: dict[str, Any]) -> None:
    limitations = report.get("limitations") or []
    errors = report.get("errors") or []
    if limitations:
        with st.expander("Limitations — what you must not conclude from this run", expanded=False):
            for item in limitations:
                st.markdown(f"- {item}")
    if errors:
        st.error("**Errors during the run**\n\n" + "\n".join(f"- {e}" for e in errors))


def _render_downloads(base: str, run_id: str) -> None:
    st.divider()
    columns = st.columns(3)
    ok_md, markdown = api_get_text(base, f"/run/{run_id}/report.md")
    if ok_md:
        columns[0].download_button(
            "⬇ report.md", markdown, file_name=f"{run_id}_report.md",
            mime="text/markdown", use_container_width=True,
        )
    ok_json, payload = api_get_text(base, f"/run/{run_id}/report")
    if ok_json:
        columns[1].download_button(
            "⬇ report.json", payload, file_name=f"{run_id}_report.json",
            mime="application/json", use_container_width=True,
        )
    ok_events, events = api_get_text(base, f"/run/{run_id}/events.jsonl")
    if ok_events:
        columns[2].download_button(
            "⬇ events.jsonl", events, file_name=f"{run_id}_events.jsonl",
            mime="application/x-ndjson", use_container_width=True,
        )


# ==========================================================================
# Entry point
# ==========================================================================
def clear_credential_state() -> None:
    """Wipe the login widgets' session state.

    Called at the top of every rerun in which a run is in progress - that is,
    on the path where the form is *not* rendered - so the assignment happens
    before any of those widgets exist. Once a run has been submitted the
    browser session has no further use for the values, and this is the only
    point at which Streamlit permits removing them.
    """
    for key in CRED_KEYS:
        st.session_state.pop(key, None)


def main() -> None:
    if "theme" not in st.session_state:
        st.session_state["theme"] = "dark"

    run_id = st.session_state.get("run_id")
    if run_id:
        clear_credential_state()

    # The dashboard intentionally has no persistent left rail. Keep the API
    # address in session state so existing sessions retain any override.
    base = st.session_state.get("api_base", DEFAULT_API)
    render_topbar()

    active_stage = get_active_stage()

    if not run_id:
        render_form(base)
        _render_recent(base)
        return

    if st.session_state.get("polling"):
        render_live(base, run_id, active_stage=active_stage)
    else:
        ok, payload = api_get(base, f"/run/{run_id}/status")
        if ok:
            render_run_header(base, run_id, payload)
            render_stage_strip(
                payload.get("current_stage", ""),
                payload.get("status", ""),
                payload.get("decision_log"),
                active_stage=active_stage,
            )
            render_metrics(payload)
            if active_stage == "decision_log":
                st.divider()
                render_decision_log(payload.get("decision_log") or [])
            else:
                render_results(base, run_id, active_stage=active_stage)
        else:
            st.error(payload)


def _render_recent(base: str) -> None:
    ok, runs = api_get(base, "/runs?limit=10", timeout=8)
    if not ok or not runs:
        return
    st.markdown(
        "<div class='form-header-wrap'><div class='section-kicker'>History</div></div>",
        unsafe_allow_html=True,
    )
    with st.expander("Recent runs"):
        for record in runs:
            columns = st.columns([3, 1, 1], vertical_alignment="center")
            columns[0].write(
                f"`{record.get('run_id')}` — {record.get('target_url')} "
                f"({record.get('status')})"
            )
            columns[1].write(f"{record.get('bug_count', 0)} bug(s)")
            if columns[2].button("Open", key=f"open_{record.get('run_id')}", use_container_width=True):
                st.session_state["run_id"] = record.get("run_id")
                st.session_state["polling"] = record.get("status") in ("queued", "running")
                st.rerun()


main()
