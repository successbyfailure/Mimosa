import subprocess

from mimosa.core.firewall import SSHIptablesFirewall


class Recorder:
    def __init__(self, stdout: str = "") -> None:
        self.calls: list[list[str]] = []
        self.stdout = stdout

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout=self.stdout, stderr="")


def test_block_and_unblock_send_commands() -> None:
    runner = Recorder()
    fw = SSHIptablesFirewall("fw.local", runner=runner)

    fw.block_ip("198.51.100.10", "test")
    fw.unblock_ip("198.51.100.10")

    assert runner.calls
    joined = " ".join(" ".join(call) for call in runner.calls)
    assert "iptables" in joined
    assert "198.51.100.10" in joined


def test_list_blocks_parses_output() -> None:
    sample_output = """Chain MIMOSA (policy ACCEPT)
num  target     prot opt source               destination
1    DROP       all  --  203.0.113.5          anywhere
2    DROP       all  --  198.51.100.2         anywhere
"""
    runner = Recorder(stdout=sample_output)
    fw = SSHIptablesFirewall("fw.local", runner=runner)

    entries = fw.list_blocks()

    assert "203.0.113.5" in entries
    assert "198.51.100.2" in entries
