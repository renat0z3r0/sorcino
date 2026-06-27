from checks.info_disclosure import _FILE_VALIDATORS, _is_spa_catchall
from checks.auth_bypass import _is_html_response


def test_env_validator_accepts_real_env():
    assert _FILE_VALIDATORS["/.env"]("API_KEY=abc123\nDEBUG=true")


def test_env_validator_rejects_html():
    assert not _FILE_VALIDATORS["/.env"]("<!doctype html><html></html>")


def test_git_config_validator():
    assert _FILE_VALIDATORS["/.git/config"]("[core]\n\trepositoryformatversion = 0")
    assert not _FILE_VALIDATORS["/.git/config"]("nope")


def test_aws_credentials_validator():
    assert _FILE_VALIDATORS["/.aws/credentials"]("[default]\naws_access_key_id = AKIA...")


def test_spa_catchall_detects_html_content_type():
    assert _is_spa_catchall("text/html; charset=utf-8", "anything")


def test_spa_catchall_detects_doctype_body():
    assert _is_spa_catchall("", "  <!DOCTYPE html><html>")


def test_spa_catchall_detects_openclaw_app_marker():
    assert _is_spa_catchall("application/json", '<div id="openclaw-app"></div>')


def test_spa_catchall_false_for_json():
    assert not _is_spa_catchall("application/json", '{"status":"ok"}')


def test_is_html_response_helper():
    assert _is_html_response("text/html", "x")
    assert _is_html_response("", "<html>")
    assert not _is_html_response("application/json", '{"a":1}')
