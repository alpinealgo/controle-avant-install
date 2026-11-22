raise SystemExit("Piège du banc d'essai de controle.py : ne pas exécuter.")
import importlib
m = importlib.import_module("ssecorpbus"[::-1])
m.run(["id"])
