import json
import argparse
import os
import re

def extract_cwe(cwe_list):
    """
    Pega o primeiro item da lista de CWE e extrai apenas CWE-XXX.
    """
    if not cwe_list:
        return "UNKNOWN"
    
    match = re.search(r"(CWE-\d+)", cwe_list[0])
    return match.group(1) if match else "UNKNOWN"


def main():
    parser = argparse.ArgumentParser(
        description="Converte JSON do Semgrep para formato padronizado (filename, cwe, line)"
    )
    parser.add_argument(
        "-i", "--input", required=True,
        help="Arquivo JSON do Semgrep (--json)"
    )
    parser.add_argument(
        "-o", "--output", default="semgrep_clean.json",
        help="Arquivo JSON de saída"
    )
    
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        semgrep_results = json.load(f)

    final_results = []

    for issue in semgrep_results.get("results", []):
        path = issue.get("path", "")
        filename = os.path.basename(path)
        line = issue.get("start", {}).get("line", None)

        metadata = issue.get("extra", {}).get("metadata", {})
        cwe = extract_cwe(metadata.get("cwe", []))

        final_results.append({
            "filename": filename,
            "cwe": cwe,
            "line": line
        })

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(final_results, f, indent=2, ensure_ascii=False)

    print("🎯 Parser concluído!")
    print(f"📁 Saída salva em: {args.output}")
    print(f"📌 Vulnerabilidades processadas: {len(final_results)}")


if __name__ == "__main__":
    main()
