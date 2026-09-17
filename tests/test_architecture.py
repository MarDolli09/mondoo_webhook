"""Architekturregeln: azyklische Importe, Teilsystem-Fassaden, reine Basispakete."""

import ast
import os
import subprocess
import sys
import unittest
from pathlib import Path

import tests  # noqa: F401  (Dummy-Umgebung)

ROOT = Path(__file__).resolve().parent.parent
SUBSYSTEMS = (
    "app.api",
    "app.services.mondoo",
    "app.services.parsing",
    "app.services.servicenow",
)


def module_name(path: Path) -> str:
    parts = list(path.relative_to(ROOT).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def import_graph() -> dict[str, set[str]]:
    """Kante = Modul, aus dessen Namensraum importiert wird."""
    modules = {module_name(p): p for p in (ROOT / "app").rglob("*.py")}
    graph: dict[str, set[str]] = {name: set() for name in modules}
    for name, path in modules.items():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            targets: list[str] = []
            if isinstance(node, ast.Import):
                targets = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                targets = [f"{node.module}.{a.name}" for a in node.names]
                targets.append(node.module)
            for target in targets:
                parts = target.split(".")
                for size in range(len(parts), 0, -1):
                    candidate = ".".join(parts[:size])
                    if candidate in modules and candidate != name:
                        graph[name].add(candidate)
                        break
    return graph


class ArchitectureTest(unittest.TestCase):
    def test_import_graph_is_acyclic(self) -> None:
        graph = import_graph()
        visiting: set[str] = set()
        done: set[str] = set()

        def visit(node: str, path: list[str]) -> None:
            if node in done:
                return
            self.assertNotIn(node, visiting, f"Zyklus: {' -> '.join([*path, node])}")
            visiting.add(node)
            for successor in sorted(graph[node]):
                visit(successor, [*path, node])
            visiting.discard(node)
            done.add(node)

        for start in sorted(graph):
            visit(start, [])

    def test_subsystems_are_used_through_their_facade(self) -> None:
        for importer, targets in import_graph().items():
            for target in targets:
                for subsystem in SUBSYSTEMS:
                    inside = importer == subsystem or importer.startswith(
                        f"{subsystem}."
                    )
                    if target.startswith(f"{subsystem}.") and not inside:
                        self.fail(f"{importer} umgeht die Fassade: {target}")

    def test_foundation_packages_import_without_environment(self) -> None:
        code = "import app.domain.ports, app.domain.priority, app.models.mondoo"
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONPATH": str(ROOT)}
        result = subprocess.run(
            [sys.executable, "-c", code],
            cwd=ROOT / "tests",
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
