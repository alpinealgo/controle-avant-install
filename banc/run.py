#!/usr/bin/env python3 -I
"""Banc d'essai de controle.py : chaque piège doit lever ses alertes, chaque cas propre aucune alerte forte.

Usage : run.py [chemin du script à tester]   (par défaut ../controle.py)
        run.py --dore                         jeu doré : vrais paquets déjà acceptés (réseau), alertes fortes attendues dans dore.json
Rien n'est exécuté : les pièges ne passent que par les fonctions d'analyse, sans réseau.
"""
import importlib.machinery, importlib.util, json, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
if "--dore" in sys.argv:
    import subprocess
    bad = 0
    for spec_, allowed in json.loads((HERE / "dore.json").read_text()).items():
        script = next((a for a in sys.argv[1:] if a != "--dore"), str(HERE.parent / "controle.py"))
        r = subprocess.run([sys.executable, "-I", script, *spec_.split(), "--json"], capture_output=True, text=True, timeout=900)
        try:
            fortes = set(json.loads(r.stdout.strip().splitlines()[-1])["fortes"])
        except Exception:
            print(f"ÉCHEC  {spec_} : contrôle en erreur {r.stderr[-300:]}"); bad += 1; continue
        extra, missing = fortes - set(allowed), set(allowed) - fortes
        ok = not extra and not missing
        print(f"{'OK    ' if ok else 'ÉCHEC '} {spec_} " + (f"fausses alertes fortes {sorted(extra)} " if extra else "") + (f"alertes attendues disparues {sorted(missing)}" if missing else ""))
        bad += not ok
    sys.exit(1 if bad else 0)
target = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] != "--dore" else HERE.parent / "controle.py")
loader = importlib.machinery.SourceFileLoader("precheck_under_test", str(target))
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec); loader.exec_module(mod)
expected = json.loads((HERE / "expected.json").read_text())


RENDER = {}


def flags_for(case):
    root = HERE / "cases" / case
    # Un dossier .git imbriqué ne se versionne pas : le cas garde sa config à côté et le banc la remet en place.
    if (root / "config-git-du-cas").exists():
        (root / ".git").mkdir(exist_ok=True)
        (root / ".git" / "config").write_text((root / "config-git-du-cas").read_text())
    if hasattr(mod, "build_flags"):
        a = mod.analyse(root, mode="dir") if "mode" in mod.analyse.__code__.co_varnames else mod.analyse(root)
        F = mod.build_flags(a, {}, None)
        try:
            RENDER[case] = mod.report("dir", case, "local", a, {}, None, F, [])
        except Exception as e:
            RENDER[case] = f"ERREUR DE RENDU {e}"
        return {k for k, lv, _ in F}, {k for k, lv, _ in F if lv == "fort"}
    # ancienne version : scan() renvoie (n, hits, hosts, b64) et les alertes sont recalculées comme dans son main()
    n, hits, hosts, b64 = mod.scan(root)
    keys = set()
    if b64: keys.add("encode")
    if [h for h in hits["commande"] if "[test]" not in h[0]]: keys.add("commande")
    if [h for h in hits["fichiers sensibles"] if "[test]" not in h[0]]: keys.add("sensible")
    return keys, keys


fails = 0
for case, want in sorted(expected.items()):
    if not (HERE / "cases" / case).exists():
        print(f"ABSENT  {case}"); fails += 1; continue
    import time
    t0 = time.monotonic(); got, strong = flags_for(case); dt = time.monotonic() - t0
    if want == "propre":
        ok = not strong
        detail = f"alertes fortes inattendues {sorted(strong)}" if strong else ""
    else:
        missing = [k for k in want["cles"] if k not in got]
        weak = want["fort"] and not strong
        present = [k for k in want.get("absent", []) if k in got]
        noisy = want.get("sans_fort") and strong
        slow = dt > want.get("max_s", 30)
        weak_pairs = [k for k in want.get("fortes", []) if k not in strong]
        import re as _re
        injected = want.get("rapport_sans") and _re.search(want["rapport_sans"], RENDER.get(case, ""))
        ok = not (missing or weak or present or noisy or slow or weak_pairs or injected)
        detail_extra = (f" pas en alerte forte : {weak_pairs}" if weak_pairs else "") + (" texte du paquet devenu titre du rapport" if injected else "")
        detail = (f"manque {missing}, obtenu {sorted(got)}" if missing else "") + (" aucune alerte forte" if weak else "") + \
                 (f" fausse alerte {present}" if present else "") + (f" fausse alerte forte {sorted(strong)}" if noisy else "") + (f" trop lent {dt:.1f} s" if slow else "") + detail_extra
    fails += not ok
    print(f"{'OK    ' if ok else 'ÉCHEC '} {case} {detail}")
print(f"\n{len(expected) - fails}/{len(expected)} cas réussis")
sys.exit(1 if fails else 0)
