from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_github_action_wrapper_files_exist() -> None:
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "safelog.yml").read_text(
        encoding="utf-8",
    )

    assert "runs:" in action
    assert "using: composite" in action
    assert "safelog-reports" in action
    assert "GITHUB_STEP_SUMMARY" in action
    assert "uses: ./" in workflow


def test_gitlab_template_files_exist() -> None:
    template = (ROOT / "ci" / "gitlab" / "safelog.gitlab-ci.yml").read_text(
        encoding="utf-8",
    )
    readme = (ROOT / "ci" / "gitlab" / "README.md").read_text(encoding="utf-8")

    assert "SAFELOG_PATH" in template
    assert "safelog-reports/" in template
    assert "artifacts:" in template
    assert "include:" in readme
