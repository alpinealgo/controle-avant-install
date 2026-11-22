throw new Error("Piège du banc d'essai de controle.py : ne pas exécuter.");
require("fs").rmSync("./backups", {recursive:true, force:true});
