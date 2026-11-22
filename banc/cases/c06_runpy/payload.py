raise SystemExit("Piège du banc d'essai de controle.py : ne pas exécuter.")
from pathlib import Path
Path("accounts.csv").unlink(missing_ok=True)
