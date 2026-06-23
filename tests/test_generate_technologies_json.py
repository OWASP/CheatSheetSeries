"""Tests for scripts/Generate_Technologies_JSON.py."""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import Generate_Technologies_JSON as tech  # noqa: E402


SAMPLE_INDEX = """\
# Index Alphabetical

**2** cheat sheets available.

[A](Index.md#a) [B](Index.md#b)

## A

[Authentication](cheatsheets/Authentication_Cheat_Sheet.md) ![Javascript](assets/Index_Javascript.svg) ![Java](assets/Index_Java.svg)

## B

[Business Logic](cheatsheets/Business_Logic_Cheat_Sheet.md) ![Java](assets/Index_Java.svg)
"""


class TestParseIndexLine:
    def test_returns_none_for_line_without_technology_icon(self):
        assert tech.parse_index_line("[Foo](cheatsheets/Foo.md)") is None

    def test_returns_none_for_blank_line(self):
        assert tech.parse_index_line("") is None
        assert tech.parse_index_line("   ") is None

    def test_parses_single_technology(self):
        cs_name, techs = tech.parse_index_line(
            "[XSS](cheatsheets/XSS.md) ![Javascript](assets/Index_Javascript.svg)"
        )
        assert cs_name == "XSS"
        assert techs == ["JAVASCRIPT"]

    def test_parses_multiple_technologies_in_order(self):
        cs_name, techs = tech.parse_index_line(
            "[Auth](cheatsheets/Auth.md) "
            "![Javascript](assets/Index_Javascript.svg) "
            "![Java](assets/Index_Java.svg) "
            "![Python](assets/Index_Python.svg)"
        )
        assert cs_name == "Auth"
        assert techs == ["JAVASCRIPT", "JAVA", "PYTHON"]

    def test_strips_leading_and_trailing_whitespace(self):
        cs_name, techs = tech.parse_index_line(
            "  [Foo](cheatsheets/Foo.md) ![Java](assets/Index_Java.svg)  "
        )
        assert cs_name == "Foo"
        assert techs == ["JAVA"]


class TestBuildTechnologiesDict:
    def test_empty_text_returns_empty_dict(self):
        assert list(tech.build_technologies_dict("").keys()) == []

    def test_groups_cheatsheets_under_their_technologies(self):
        result = tech.build_technologies_dict(SAMPLE_INDEX)
        # Authentication is under Javascript and Java; Business Logic
        # is under Java only.
        assert "JAVASCRIPT" in result
        assert "JAVA" in result
        assert len(result["JAVASCRIPT"]) == 1
        assert result["JAVASCRIPT"][0]["CS_NAME"] == "Authentication"
        assert len(result["JAVA"]) == 2
        java_cs_names = {entry["CS_NAME"] for entry in result["JAVA"]}
        assert java_cs_names == {"Authentication", "Business Logic"}

    def test_uses_owasp_cheatsheets_url_for_cs_url(self):
        result = tech.build_technologies_dict(SAMPLE_INDEX)
        auth_entry = result["JAVASCRIPT"][0]
        assert (
            auth_entry["CS_URL"]
            == "https://cheatsheetseries.owasp.org/cheatsheets/Authentication.html"
        )

    def test_ignores_lines_without_technology_icons(self):
        text = (
            "# Title\n\n"
            "Some intro text.\n\n"
            "[Foo](cheatsheets/Foo.md) ![Java](assets/Index_Java.svg)\n"
        )
        result = tech.build_technologies_dict(text)
        # Only the icon line produced an entry; the title and intro
        # are ignored.
        assert list(result.keys()) == ["JAVA"]
        assert result["JAVA"][0]["CS_NAME"] == "Foo"

    def test_preserves_insertion_order_of_technologies(self):
        # Technologies should be discovered in document order, not
        # alphabetical order, matching the legacy OrderedDict behavior.
        result = tech.build_technologies_dict(SAMPLE_INDEX)
        assert list(result.keys()) == ["JAVASCRIPT", "JAVA"]


class TestFetchIndexText:
    def test_returns_status_code_and_body(self):
        fake_response = mock.Mock(status_code=200, text="# Index\n")
        with mock.patch.object(tech.requests, "get", return_value=fake_response):
            status, body = tech.fetch_index_text()
        assert status == 200
        assert body == "# Index\n"

    def test_uses_default_index_url(self):
        fake_response = mock.Mock(status_code=200, text="")
        with mock.patch.object(
            tech.requests, "get", return_value=fake_response
        ) as get_mock:
            tech.fetch_index_text()
        assert get_mock.call_args.args[0] == tech.INDEX_URL


class TestMain:
    def test_prints_json_and_exits_zero_on_success(self, capsys):
        fake_response = mock.Mock(status_code=200, text=SAMPLE_INDEX)
        with mock.patch.object(tech.requests, "get", return_value=fake_response):
            rc = tech.main()
        assert rc == 0
        captured = capsys.readouterr()
        # The output should be valid JSON, formatted with indent=1.
        parsed = json.loads(captured.out)
        assert "JAVASCRIPT" in parsed
        assert "JAVA" in parsed

    def test_exits_one_on_non_200_status(self, capsys):
        fake_response = mock.Mock(status_code=404, text="")
        with mock.patch.object(tech.requests, "get", return_value=fake_response):
            rc = tech.main()
        assert rc == 1
        captured = capsys.readouterr()
        assert "HTTP 404" in captured.out
        # On error, no JSON is emitted to stdout.
        assert captured.out.strip().endswith("received!")

    def test_exits_one_on_connection_error(self, capsys):
        # Network failures should propagate from requests.get; the
        # script does not currently catch them, so we only verify
        # that the script does not silently succeed.
        with mock.patch.object(
            tech.requests,
            "get",
            side_effect=tech.requests.RequestException("boom"),
        ):
            with pytest.raises(tech.requests.RequestException):
                tech.main()
