"""Extract APP_VERSION from config.py without importing any third-party dependencies."""
from pathlib import Path


def get_app_version() -> str:
    config_file = Path(__file__).resolve().parent.parent / "config.py"
    with open(config_file, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("APP_VERSION"):
                return line.split("=")[1].strip().strip("\"'").lstrip("v")
    return "0.0.0"


if __name__ == "__main__":
    print(get_app_version())
