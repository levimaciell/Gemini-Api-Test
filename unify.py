import json
import os
import argparse

EXPECTED_FILES = {
    "Bandit": "formatted_bandit.json",
    "Semgrep": "formatted_semgrep.json",
    "SonarQube": "formatted_sonarqube.json"
}


def load_json_if_exists(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                print(f"⚠️ Erro ao decodificar JSON: {path}")
                return []
    else:
        print(f"⚠️ Arquivo não encontrado: {path}")
        return []


def normalize_entry(entry, tool):
    filename = os.path.basename(entry.get("filename", ""))
    return {
        "filename": filename,
        "cwe": entry.get("cwe", "").upper(),
        "line": entry.get("line", None),
        "tool": tool
    }


def fuse_results(base_dir):
    merged = {}

    for tool, filename in EXPECTED_FILES.items():
        filepath = os.path.join(base_dir, filename)
        data = load_json_if_exists(filepath)

        for entry in data:
            e = normalize_entry(entry, tool)
            key = (e["filename"], e["cwe"], e["line"])

            if key not in merged:
                merged[key] = {
                    "filename": e["filename"],
                    "cwe": e["cwe"],
                    "line": e["line"],
                    "tools": set()
                }

            merged[key]["tools"].add(tool)

    # converter sets para listas
    for item in merged.values():
        item["tools"] = list(item["tools"])

    return list(merged.values())


def main():
    parser = argparse.ArgumentParser(description="Funde resultados SAST padronizados em um único JSON.")
    
    parser.add_argument(
        "-d", "--directory", required=True,
        help="Diretório contendo os JSONs do SAST"
    )

    parser.add_argument(
        "-o", "--output", default="SAST_Fused.json",
        help="Arquivo JSON de saída"
    )

    args = parser.parse_args()
    base_dir = os.path.abspath(args.directory)

    print(f"📁 Procurando arquivos em: {base_dir}")
    fused = fuse_results(base_dir)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(fused, f, indent=2, ensure_ascii=False)

    print("\n🎯 Fusão concluída!")
    print(f"📌 Vulnerabilidades unificadas: {len(fused)}")
    print(f"📁 Saída salva em: {args.output}")


if __name__ == "__main__":
    main()
