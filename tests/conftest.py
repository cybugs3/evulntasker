import os
from pathlib import Path

os.environ.setdefault("EVULNTASKER_DATABASE_URL", "sqlite:///./data/evulntasker.db")
Path("./data").mkdir(parents=True, exist_ok=True)
