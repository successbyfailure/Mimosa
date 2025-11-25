import os
from pathlib import Path

from conftest import ensure_test_env


def test_ensure_test_env_loads_export_prefixed_lines(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "# comentario", 
                "export TEST_FIREWALL_OPNSENSE_BASE_URL=https://fw.example", 
                "export TEST_FIREWALL_OPNSENSE_API_KEY=abc123", 
                "export TEST_FIREWALL_OPNSENSE_API_SECRET=shhh",
            ]
        )
    )

    os.environ.pop("TEST_FIREWALL_OPNSENSE_BASE_URL", None)
    os.environ.pop("TEST_FIREWALL_OPNSENSE_API_KEY", None)
    os.environ.pop("TEST_FIREWALL_OPNSENSE_API_SECRET", None)

    assert ensure_test_env(
        {
            "TEST_FIREWALL_OPNSENSE_BASE_URL",
            "TEST_FIREWALL_OPNSENSE_API_KEY",
            "TEST_FIREWALL_OPNSENSE_API_SECRET",
        },
        env_paths=[env_file],
    )

    assert os.environ["TEST_FIREWALL_OPNSENSE_BASE_URL"] == "https://fw.example"
    assert os.environ["TEST_FIREWALL_OPNSENSE_API_KEY"] == "abc123"
    assert os.environ["TEST_FIREWALL_OPNSENSE_API_SECRET"] == "shhh"
