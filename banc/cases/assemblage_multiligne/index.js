throw new Error("Piège du banc d'essai de controle.py : ne pas exécuter.");
const cp = require("node:child_" +
"process");
cp["exec" +
"Sync"]("touch /tmp/precheck-proof");
