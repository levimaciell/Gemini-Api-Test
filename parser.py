import json
import argparse
import os

# Yes, it was made with AI

def main():
    parser = argparse.ArgumentParser(
        description="Converte JSON do Bandit para formato padronizado de labels (CWE + linha)"
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Arquivo JSON de entrada (output do Bandit)"
    )
    parser.add_argument(
        "-o", "--output", default="bandit_labels.json",
        help="Arquivo JSON de saída (default: bandit_labels.json)"
    )

    args = parser.parse_args()

    # Abrir arquivo do Bandit
    with open(args.input, "r", encoding="utf-8") as f:
        bandit_data = json.load(f)

    # Lista final de labels padronizados
    labels = []

    for issue in bandit_data.get("results", []):
        filename = issue.get("filename")
        line = issue.get("line_number")

        cwe_info = issue.get("issue_cwe", {})
        cwe_id = cwe_info.get("id")

        if cwe_id is None:
            # Caso não tenha CWE (raro, mas pode acontecer)
            continue

        label = {
            "filename": filename,
            "cwe": f"CWE-{cwe_id}",
            "line": line
        }
        labels.append(label)

    # Salva o JSON padronizado
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2, ensure_ascii=False)

    print(f"✔️ Conversão concluída!")
    print(f"➡️ Arquivo gerado: {os.path.abspath(args.output)}")
    print(f"📦 {len(labels)} labels extraídas com sucesso!")

if __name__ == "__main__":
    main()
