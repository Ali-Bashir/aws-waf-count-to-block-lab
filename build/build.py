"""Embed src/*.py into template.yaml (CloudFormation inline ZipFile code)."""
import pathlib
root = pathlib.Path(__file__).resolve().parent.parent
tpl = (root / "build" / "template.in.yaml").read_text()
def indent(p):
    return "\n".join(("          " + l) if l.strip() else "" for l in (root / "src" / p).read_text().rstrip("\n").split("\n"))
out = tpl.replace("{{ECHO}}", indent("echo.py")).replace("{{TRAFFIC}}", indent("traffic.py"))
(root / "template.yaml").write_text(out)
for p in ["echo.py", "traffic.py"]:
    assert len((root / "src" / p).read_text()) < 4096, p
print("template.yaml written")
