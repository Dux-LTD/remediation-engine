"""Classify every catalog component with TypeSafe, in parallel.

Separate from the remediation tool. The TypeSafe key is read from the
1Password item "Jev Amit Tests" (credential field, vault dev-secrets),
unless TYPESAFE_API_KEY is already set.

Writes two files under scripts/results/os_non_os/:
  confident.json  — top answer at 70% or above
  rest.json       — top answer below 70%

  - answer: OS, Non-OS, Ignore (after human review, decided to be out of the catalog)
  - percentage: percentage - Jev's classification, human_review - classified by human

The percentage is the probability of the selected option. Already saved
components are skipped, so a stopped run can be continued.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from typesafe_sdk import Choice, TypeSafeClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from defs.def_components import SOFTWARE_COMPONENTS  # noqa: E402

SCRIPTS = Path(__file__).resolve().parent
RESULTS = SCRIPTS / "results" / "os_non_os"
CONFIDENT_PATH = RESULTS / "confident.json"
REST_PATH = RESULTS / "rest.json"
CONFIDENT_AT = 70.0
API_KEY_REF = "op://dev-secrets/Jev Amit Tests/credential"
PROMPT_FILE = "jev_software_classification.json"

def prompt_text(value: str) -> str:
    """Drop quotes and newlines so the value can sit inside a single-quoted prompt."""
    return " ".join(value.replace('"', "").replace("'", "").split())


_PROMPT = json.loads((SCRIPTS / PROMPT_FILE).read_text(encoding="utf-8"))[
    "os_classification"
]
INSTRUCTIONS = _PROMPT["instructions"]
CRITERIA = _PROMPT["criteria"]


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def save(path: Path, rows: list[dict]) -> None:
    path.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")


def classify_one(component) -> dict:
    with TypeSafeClient() as client:
        response = client.system_one(
            state={
                "component": component.display_name,
                "description": prompt_text(component.description),
            },
            questions={
                "os_classification": Choice(
                    instructions=INSTRUCTIONS,
                    criteria=CRITERIA,
                )
            },
        )
    answer = response.choices["os_classification"]
    percentage = round(answer.probabilities[answer.choice] * 100, 1)
    return {
        "component": component.display_name,
        "answer": answer.choice,
        "percentage": percentage,
    }


def load_api_key() -> None:
    """Read the TypeSafe key from 1Password when the environment has none."""
    if os.environ.get("TYPESAFE_API_KEY"):
        return
    result = subprocess.run(
        ["op", "read", API_KEY_REF],
        check=True,
        capture_output=True,
        text=True,
    )
    os.environ["TYPESAFE_API_KEY"] = result.stdout.strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None, help="classify only the first N components")
    parser.add_argument(
        "--threads",
        type=int,
        default=8,
        help="parallel TypeSafe requests (default 8)",
    )
    args = parser.parse_args()

    load_api_key()
    RESULTS.mkdir(parents=True, exist_ok=True)
    confident = load(CONFIDENT_PATH)
    rest = load(REST_PATH)
    done = {row["component"] for row in confident + rest}
    all_components = list(SOFTWARE_COMPONENTS.values())
    components = all_components[: args.limit] if args.limit else all_components
    pending = [c for c in components if c.display_name not in done]
    lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        futures = [pool.submit(classify_one, component) for component in pending]
        for future in as_completed(futures):
            row = future.result()
            with lock:
                bucket = confident if row["percentage"] >= CONFIDENT_AT else rest
                bucket.append(row)
                save(CONFIDENT_PATH, confident)
                save(REST_PATH, rest)
            print(f"{row['component']}: {row['answer']} {row['percentage']}%", flush=True)

    print(
        f"confident: {len(confident)}  rest: {len(rest)}",
        flush=True,
    )


if __name__ == "__main__":
    main()
