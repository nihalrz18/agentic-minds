"""Tests for the workflow stage strip states, header, and styling in Streamlit."""

from __future__ import annotations

import re
from unittest.mock import patch, MagicMock
import pytest

from ui.streamlit_app import (
    STAGES,
    render_stage_strip,
    render_run_header,
    render_decision_log,
    render_live_stage_details,
    render_results,
    render_topbar,
    get_logo_data_uri,
    render_form,
    inject_styles,
    render_metrics,
)


class TestStageStripStates:
    def _capture_markdown(self, current: str, status: str, decision_log=None, active_stage="overview") -> str:
        captured = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured.append(html)):
            render_stage_strip(current, status, decision_log, active_stage=active_stage)
        return captured[0] if captured else ""

    def test_running_stage_has_running_class_and_badge(self):
        html = self._capture_markdown("planner", "running")
        # Planner should be marked running with the RUNNING badge
        assert "stage-node running" in html
        assert "<span class='stage-status-badge'>RUNNING</span>" in html
        # Subsequent stages (coverage_gate, etc.) should be pending
        assert "stage-node pending" in html
        assert "<span class='stage-status-badge'>PENDING</span>" in html

    def test_executed_planner_when_at_coverage_gate(self):
        html = self._capture_markdown("coverage_gate", "running")
        # Planner (position 0) must be executed (done / succeeded)
        planner_block = re.search(r"stage-node ([^>]*done[^>]*>.*?planner.*?</div>\s*</a>)", html, re.DOTALL | re.IGNORECASE)
        assert planner_block is not None
        assert "done" in planner_block.group(0)
        assert "<span class='stage-status-badge'>SUCCEEDED</span>" in planner_block.group(0)

        # Coverage gate (position 1) must be running
        coverage_block = re.search(r"stage-node ([^>]*running[^>]*>.*?coverage gate.*?</div>\s*</a>)", html, re.DOTALL | re.IGNORECASE)
        assert coverage_block is not None
        assert "running" in coverage_block.group(0)
        assert "<span class='stage-status-badge'>RUNNING</span>" in coverage_block.group(0)

        # Risk ranking (position 2) must be pending
        risk_block = re.search(r"stage-node ([^>]*pending[^>]*>.*?risk ranking.*?</div>\s*</a>)", html, re.DOTALL | re.IGNORECASE)
        assert risk_block is not None
        assert "pending" in risk_block.group(0)
        assert "<span class='stage-status-badge'>PENDING</span>" in risk_block.group(0)

    def test_completed_run_marks_all_stages_succeeded(self):
        html = self._capture_markdown("report", "completed")
        assert "stage-node running" not in html
        assert "stage-node pending" not in html
        assert html.count("stage-node done") == len(STAGES)
        assert html.count("<span class='stage-status-badge'>SUCCEEDED</span>") == len(STAGES)

    def test_failed_run_marks_failed_stage(self):
        html = self._capture_markdown("runner", "failed")
        runner_block = re.search(r"stage-node ([^>]*failed[^>]*>.*?runner.*?</div>\s*</a>)", html, re.DOTALL | re.IGNORECASE)
        assert runner_block is not None
        assert "failed" in runner_block.group(0)
        assert "<span class='stage-status-badge'>FAILED</span>" in runner_block.group(0)

    def test_failed_planner_marks_subsequent_stages_skipped_not_succeeded(self):
        decision_log = [
            {"stage": "orchestrator", "event": "start", "summary": "Run started"},
            {"stage": "planner", "event": "start", "summary": "planner started"},
            {"stage": "planner", "event": "error", "summary": "planner failed: rate limit 429"},
            {"stage": "report", "event": "start", "summary": "report started"},
            {"stage": "report", "event": "complete", "summary": "report complete"},
        ]
        html = self._capture_markdown("report", "failed", decision_log=decision_log)

        # Planner must be marked FAILED
        planner_block = re.search(r"stage-node ([^>]*failed[^>]*>.*?planner.*?</div>\s*</a>)", html, re.DOTALL | re.IGNORECASE)
        assert planner_block is not None
        assert "FAILED" in planner_block.group(0)

        # Downstream unexecuted stages must NOT be marked SUCCEEDED; they must be SKIPPED
        assert html.count("<span class='stage-status-badge'>SUCCEEDED</span>") == 1  # only report completed
        for stage in ["coverage_gate", "risk_ranking", "generator", "runner", "healer", "visual_diff", "bug_packager"]:
            block = re.search(rf"stage-node ([^>]*pending[^>]*>.*?{stage.replace('_', ' ')}.*?</div>\s*</a>)", html, re.DOTALL | re.IGNORECASE)
            assert block is not None, f"Stage {stage} should be pending/skipped"
            assert "SKIPPED" in block.group(0), f"Stage {stage} should have SKIPPED badge"
            assert "SUCCEEDED" not in block.group(0), f"Stage {stage} must NOT be SUCCEEDED"

        # Report completed synthesizing the failure report so it is SUCCEEDED
        report_block = re.search(r"stage-node ([^>]*done[^>]*>.*?report.*?</div>\s*</a>)", html, re.DOTALL | re.IGNORECASE)
        assert report_block is not None
        assert "SUCCEEDED" in report_block.group(0)

    def test_failed_runner_marks_earlier_succeeded_and_later_skipped(self):
        decision_log = [
            {"stage": "planner", "event": "complete", "summary": "planner complete"},
            {"stage": "coverage_gate", "event": "complete", "summary": "gate complete"},
            {"stage": "risk_ranking", "event": "complete", "summary": "ranking complete"},
            {"stage": "generator", "event": "complete", "summary": "generator complete"},
            {"stage": "runner", "event": "error", "summary": "runner failed: tests failed"},
            {"stage": "report", "event": "complete", "summary": "report complete"},
        ]
        html = self._capture_markdown("report", "failed", decision_log=decision_log)
        # planner, coverage_gate, risk_ranking, generator, report -> 5 SUCCEEDED
        assert html.count("<span class='stage-status-badge'>SUCCEEDED</span>") == 5
        # runner -> 1 FAILED
        assert html.count("<span class='stage-status-badge'>FAILED</span>") == 1
        # healer, visual_diff, bug_packager -> 3 SKIPPED
        assert html.count("<span class='stage-status-badge'>SKIPPED</span>") == 3

    def test_cancelled_run_marks_unexecuted_stages_skipped(self):
        decision_log = [
            {"stage": "planner", "event": "complete", "summary": "planner complete"},
            {"stage": "coverage_gate", "event": "complete", "summary": "gate complete"},
        ]
        html = self._capture_markdown("risk_ranking", "cancelled", decision_log=decision_log)
        assert "<span class='stage-status-badge'>CANCELLED</span>" in html
        assert "<span class='stage-status-badge'>SKIPPED</span>" in html


    def test_all_stages_have_native_tooltips(self):
        html = self._capture_markdown("planner", "running")
        for stage in STAGES:
            assert "title=" in html

    def test_stage_nodes_are_interactive_anchor_links(self):
        html = self._capture_markdown("planner", "running")
        for stage in STAGES:
            assert f"?stage={stage}#stage-{stage}" in html
            assert "target='_self'" in html

    def test_stage_node_active_class_when_selected(self):
        html = self._capture_markdown("planner", "running", active_stage="planner")
        assert "stage-node running active" in html

    def test_pipeline_header_does_not_contain_all_overview_or_live_trace(self):
        html = self._capture_markdown("planner", "running")
        assert "All Overview" not in html
        assert "Live Trace" not in html
        assert "Pipeline Execution Flow" in html

    def test_css_contains_yellow_blink_and_no_broken_after_tooltip(self):
        from pathlib import Path
        css_file = Path(__file__).parent.parent / "ui" / "streamlit_app.py"
        content = css_file.read_text(encoding="utf-8")

        # Yellow blink animation definition and usage must exist
        assert "@keyframes yellow-blink" in content
        assert "animation: yellow-blink" in content

        # Broken :after pseudo-element with attr(data-tooltip) must NOT exist
        assert "content: attr(data-tooltip)" not in content
        assert ".stage-node:after" not in content

        # Smooth scrolling and stage anchor offsets must exist
        assert "scroll-behavior: smooth" in content
        assert ".stage-section-anchor" in content

    def test_typography_system_is_consistent_and_no_playfair(self):
        from pathlib import Path
        css_file = Path(__file__).parent.parent / "ui" / "streamlit_app.py"
        content = css_file.read_text(encoding="utf-8")

        # Playfair Display serif font must NOT be used anywhere
        assert "Playfair" not in content
        assert "Georgia" not in content

        # Unified font families must be defined and applied
        assert "--font-sans" in content
        assert "--font-mono" in content
        assert "'Manrope'" in content
        assert "'DM Mono'" in content


class TestDecisionLogInversion:
    def test_newest_event_on_top_and_old_down(self):
        events = [
            {"stage": "planner", "event": "start", "summary": "Oldest event 1", "ts": "2026-09-05T10:00:00Z"},
            {"stage": "coverage_gate", "event": "complete", "summary": "Middle event 2", "ts": "2026-09-05T10:01:00Z"},
            {"stage": "runner", "event": "error", "summary": "Newest event 3", "ts": "2026-09-05T10:02:00Z"},
        ]
        captured_md = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured_md.append(html)), \
             patch("streamlit.subheader"), patch("streamlit.caption"), patch("streamlit.container"):
            render_decision_log(events)

        combined_html = "\n".join(captured_md)
        pos_oldest = combined_html.find("Oldest event 1")
        pos_middle = combined_html.find("Middle event 2")
        pos_newest = combined_html.find("Newest event 3")

        # In UI, new update should come on top and old should show down:
        assert pos_newest != -1
        assert pos_middle != -1
        assert pos_oldest != -1
        assert pos_newest < pos_middle < pos_oldest

        # Newest event must have LATEST badge
        assert "<span class='log-badge-latest'>● LATEST</span>" in combined_html

        # Stage jump links must exist for each event using ?stage=
        assert "href='?stage=runner'" in combined_html
        assert "href='?stage=coverage_gate'" in combined_html
        assert "href='?stage=planner'" in combined_html


class TestStageAnchors:
    def test_live_stage_details_has_anchors_for_all_stages(self):
        captured_md = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured_md.append(html)), \
             patch("streamlit.subheader"), patch("streamlit.caption"), patch("streamlit.expander"):
            render_live_stage_details("planner", "running", [], {})

        combined_html = "\n".join(captured_md)
        for stage in STAGES:
            assert f"id='stage-{stage}'" in combined_html

    def test_results_has_anchors_for_all_stages(self):
        mock_report = {
            "executive_summary": "Test summary",
            "business_impact": "High",
            "flows": [{"flow_id": "flow_1", "flow_name": "Login", "status": "passed"}],
            "coverage_evaluation": {"score": 100, "passed": True},
            "packaged_bugs": [],
            "visual_findings": [],
            "needs_human_review": [],
            "healer_actions": [],
            "prd_gaps": [],
            "regression_radar": {},
        }
        captured_md = []
        with patch("ui.streamlit_app.api_get", return_value=(True, mock_report)), \
             patch("ui.streamlit_app.api_get_text", return_value=(True, "sample")), \
             patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured_md.append(html)), \
             patch("streamlit.header"), patch("streamlit.subheader"), patch("streamlit.caption"), \
             patch("streamlit.divider"), patch("streamlit.success"), patch("streamlit.info"), \
             patch("streamlit.columns", return_value=[MagicMock(), MagicMock(), MagicMock()]), \
             patch("streamlit.dataframe"), patch("streamlit.expander"):
            render_results("http://127.0.0.1:8000", "test_run")

        combined_html = "\n".join(captured_md)
        for stage in STAGES:
            assert f"id='stage-{stage}'" in combined_html


class TestRunHeader:
    def test_header_shows_running_for_target_url(self):
        captured_md = []
        buttons = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured_md.append(html)), \
             patch("streamlit.button", side_effect=lambda label, **kwargs: buttons.append((label, kwargs))):
            payload = {
                "status": "running",
                "target_url": "https://demoqa.com",
            }
            render_run_header("http://127.0.0.1:8000", "run_5115a3520f9e", payload)

        header_html = "\n".join(captured_md)
        assert "Running for" in header_html
        assert "https://demoqa.com" in header_html
        assert "run_5115a3520f9e" in header_html

        button_keys = [kwargs.get("key") for _, kwargs in buttons]
        assert "start_another_run" in button_keys
        assert "cancel_run" in button_keys

    def test_header_shows_completed_for_target_url(self):
        captured_md = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured_md.append(html)), \
             patch("streamlit.button", return_value=False):
            payload = {
                "status": "completed",
                "target_url": "https://demoqa.com",
            }
            render_run_header("http://127.0.0.1:8000", "run_0a2bf28f9228", payload)

        header_html = "\n".join(captured_md)
        assert "Completed for" in header_html
        assert "https://demoqa.com" in header_html


class TestAgenticMindsBrandingAndDeployRemoval:
    def test_css_removes_deploy_button_and_toolbar(self):
        from pathlib import Path
        css_file = Path(__file__).parent.parent / "ui" / "streamlit_app.py"
        content = css_file.read_text(encoding="utf-8")

        # Streamlit deploy button selectors must be set to display: none / hidden
        assert '[data-testid="stDeployButton"]' in content
        assert ".stDeployButton" in content
        assert 'header [data-testid="stToolbar"]' in content
        assert 'header[data-testid="stHeader"]' in content

    def test_get_logo_data_uri_returns_valid_uri(self):
        uri = get_logo_data_uri()
        assert uri.startswith("data:image/")
        assert len(uri) > 100

    def test_render_topbar_displays_agentic_minds_brand_and_logo(self):
        captured_md = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured_md.append(html)):
            render_topbar()

        topbar_html = "\n".join(captured_md)
        assert "Agentic Minds" in topbar_html
        assert "Autonomous Test Orchestration" in topbar_html
        # Redundant right side badge was removed per user request
        assert "hackathon-badge" not in topbar_html
        assert "brand-logo-img" in topbar_html
        assert "data:image/" in topbar_html

    def test_render_form_displays_agentic_minds_eyebrow(self):
        captured_md = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured_md.append(html)), \
             patch("streamlit.form"):
            render_form("http://127.0.0.1:8000")

        form_html = "\n".join(captured_md)
        assert "Hackathon Team · Agentic Minds" in form_html
        assert "Engineered by <strong>Agentic Minds</strong>" in form_html

    def test_css_removes_accessibility_and_stop_buttons(self):
        from pathlib import Path
        css_file = Path(__file__).parent.parent / "ui" / "streamlit_app.py"
        content = css_file.read_text(encoding="utf-8")

        # Accessibility icon and Stop button selectors must be hidden
        assert '[aria-label="Accessibility"]' in content
        assert 'button[title="Stop execution"]' in content
        assert 'button[title="Stop"]' in content
        assert '[data-testid="stStatusWidget"]' in content

    def test_form_animation_and_medium_font_sizes(self):
        from pathlib import Path
        css_file = Path(__file__).parent.parent / "ui" / "streamlit_app.py"
        content = css_file.read_text(encoding="utf-8")

        # Form glowing border animation
        assert "@keyframes form-border-glow" in content
        assert "animation: form-border-glow" in content

        # Medium typography (at least medium: 1.02rem)
        assert "font-size: 1.02rem" in content

        # Button background is NOT glaring white #efeff8
        assert "background: #efeff8" not in content

    def test_inject_styles_dark_and_light_themes(self):
        captured_md = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured_md.append(html)):
            inject_styles("dark")
            inject_styles("light")

        assert len(captured_md) == 2
        dark_css = captured_md[0]
        light_css = captured_md[1]

        # Dark theme check
        assert "#08090d" in dark_css
        assert "#111218" in dark_css

        # Light theme check
        assert "#f8f9fc" in light_css
        assert "#ffffff" in light_css

    def test_render_topbar_contains_theme_toggle(self):
        captured_toggle = []
        with patch("streamlit.markdown"), \
             patch("streamlit.columns", return_value=[MagicMock(), MagicMock()]), \
             patch("streamlit.toggle", side_effect=lambda label, **kwargs: captured_toggle.append(label)):
            render_topbar()

        assert len(captured_toggle) == 1
        assert "Mode" in captured_toggle[0]


class TestStageRoutingAndWindowView:
    def test_render_stage_navigation_bar_renders_all_stages_and_active_pill(self):
        from ui.streamlit_app import render_stage_navigation_bar
        captured = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured.append(html)):
            render_stage_navigation_bar("generator")

        html = captured[0]
        assert "stage-nav-wrap" in html
        assert "href='?stage=generator' class='stage-nav-pill active'" in html
        assert "href='?stage=planner' class='stage-nav-pill'" in html
        assert "href='?stage=overview' class='stage-nav-pill'" in html

    def test_render_results_shows_active_stage_banner_and_content(self):
        mock_report = {
            "executive_summary": "Test summary",
            "business_impact": "High",
            "flows": [{"flow_id": "flow_1", "flow_name": "Login Flow", "status": "passed", "code": "page.goto('/')"}],
            "coverage_evaluation": {"score": 100, "passed": True},
            "packaged_bugs": [],
            "visual_findings": [],
            "needs_human_review": [],
            "healer_actions": [],
            "prd_gaps": [],
            "regression_radar": {},
        }
        captured_md = []
        with patch("ui.streamlit_app.api_get", return_value=(True, mock_report)), \
             patch("ui.streamlit_app.api_get_text", return_value=(True, "sample")), \
             patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured_md.append(html)), \
             patch("streamlit.header"), patch("streamlit.subheader"), patch("streamlit.caption"), \
             patch("streamlit.divider"), patch("streamlit.success"), patch("streamlit.info"), \
             patch("streamlit.columns", return_value=[MagicMock(), MagicMock(), MagicMock()]), \
             patch("streamlit.dataframe"), patch("streamlit.expander"):
            render_results("http://127.0.0.1:8000", "test_run", active_stage="generator")

        combined = "\n".join(captured_md)
        assert "Viewing Stage: <strong>Generator</strong>" in combined
        assert "Stage · Generator" in combined

    def test_css_sleek_flow_strip_and_compact_metrics(self):
        from pathlib import Path
        css_file = Path(__file__).parent.parent / "ui" / "streamlit_app.py"
        content = css_file.read_text(encoding="utf-8")

        # Responsive flow strip and active node
        assert ".stage-node" in content
        assert ".stage-node.active" in content
        assert "yellow-blink" in content

        # Metric compaction ribbon for single window view
        assert ".metrics-ribbon" in content
        assert ".metric-item" in content




class TestRenderMetrics:
    def test_elapsed_time_formats_minutes_and_seconds(self):
        # 1548 seconds = 25m 48s
        payload = {
            "current_stage": "runner",
            "started_at": "2026-09-05T10:00:00+00:00",
            "finished_at": "2026-09-05T10:25:48+00:00",
            "counts": {"tests_generated": 10, "passed": 8, "failed": 2},
        }
        captured = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured.append(html)):
            render_metrics(payload)

        assert len(captured) == 1
        html = captured[0]
        assert "<span class='m-lbl'>ELAPSED</span><span class='m-val'>25m 48s</span>" in html

    def test_elapsed_time_under_a_minute(self):
        # 42 seconds = 42s
        payload = {
            "current_stage": "planner",
            "started_at": "2026-09-05T10:00:00+00:00",
            "finished_at": "2026-09-05T10:00:42+00:00",
        }
        captured = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured.append(html)):
            render_metrics(payload)

        assert "<span class='m-lbl'>ELAPSED</span><span class='m-val'>42s</span>" in captured[0]

    def test_elapsed_time_over_an_hour(self):
        # 3725 seconds = 1h 2m 5s
        payload = {
            "current_stage": "report",
            "started_at": "2026-09-05T10:00:00+00:00",
            "finished_at": "2026-09-05T11:02:05+00:00",
        }
        captured = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured.append(html)):
            render_metrics(payload)

        assert "<span class='m-lbl'>ELAPSED</span><span class='m-val'>1h 2m 5s</span>" in captured[0]

    def test_edge_round_corner_cards_render_all_ten_metrics(self):
        payload = {
            "current_stage": "report",
            "started_at": "2026-09-05T10:00:00+00:00",
            "finished_at": "2026-09-05T10:25:48+00:00",
            "replan_count": 0,
            "counts": {
                "flows": 0,
                "tests_generated": 10,
                "passed": 0,
                "failed": 9,
                "healed": 1,
                "bugs_filed": 0,
                "visual_regressions": 5,
            },
        }
        captured = []
        with patch("streamlit.markdown", side_effect=lambda html, **kwargs: captured.append(html)):
            render_metrics(payload)

        html = captured[0]
        assert "metrics-grid" in html
        assert html.count("metric-card") == 10
        for label in ("STAGE", "ELAPSED", "RE-PLANS", "FLOWS", "TESTS", "PASSED", "FAILED", "HEALED", "BUGS FILED", "VISUAL REGRESSIONS"):
            assert f"<span class='m-lbl'>{label}</span>" in html

        from pathlib import Path
        css_file = Path(__file__).parent.parent / "ui" / "streamlit_app.py"
        content = css_file.read_text(encoding="utf-8")
        assert "border-radius: 14px" in content
        assert ".metric-card" in content





