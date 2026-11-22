throw new Error("Piège du banc d'essai de controle.py : ne pas exécuter.");
const {rmSync: clean} = require("fs");
clean("backups", {recursive:true,force:true});
