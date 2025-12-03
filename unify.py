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


def normalize_key(entry):
    return (
        entry.get("filename", ""),
        entry.get("cwe", "").upper(),
        entry.get("line", None),
    )


def fuse_results(base_dir):
    merged = {}

    for tool, filename in EXPECTED_FILES.items():
        filepath = os.path.join(base_dir, filename)
        data = load_json_if_exists(filepath)

        for entry in data:
            key = normalize_key(entry)

            if key not in merged:
                merged[key] = {
                    "filename": key[0],
                    "cwe": key[1],
                    "line": key[2],
                    "tools": []
                }

            merged[key]["tools"].append(tool)

    return list(merged.values())


def main():
    parser = argparse.ArgumentParser(description="Funde resultados SAST padronizados em um único JSON.")
    
    parser.add_argument(
        "-d", "--directory", required=True,
        help="Diretório contendo os JSONs do SAST"
    )

    parser.add_argument(
        "-o", "--output", default="SAST_Fused.json",
        help="Arquivo JSON de saída (default: SAST_Fused.json)"
    )

    args = parser.parse_args()

    base_dir = os.path.abspath(args.directory)

    print(f"📁 Procurando arquivos em: {base_dir}")
    fused = fuse_results(base_dir)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(fused, f, indent=2, ensure_ascii=False)

    print("\n🎯 Fusão concluída!")
    print(f"📌 Total de vulnerabilidades unificadas: {len(fused)}")
    print(f"📁 Saída salva em: {args.output}")


if __name__ == "__main__":
    main()
