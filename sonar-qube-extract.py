import argparse
import requests
import json
import os

def fetch_all_issues(sonar_url, project_key, token):
    issues = []
    page = 1
    page_size = 500  # Max page size permitted by API

    while True:
        endpoint = (
            f"{sonar_url}/api/issues/search?"
            f"componentKeys={project_key}&"
            f"types=VULNERABILITY&"
            f"ps={page_size}&p={page}"
        )

        response = requests.get(endpoint, auth=(token, ""))
        if response.status_code != 200:
            print(f"Erro ao consultar SonarQube API: {response.status_code}")
            print(response.text)
            break

        data = response.json()
        issues.extend(data.get("issues", []))

        if page * page_size >= data.get("paging", {}).get("total", 0):
            break

        page += 1

    return issues


def normalize_issue(issue):
    cwe = None
    if "cwe" in issue.get("rule", "").lower():
        # Tenta extrair o número do final da regra, ex: python:S2076 → S2076
        cwe = issue.get("rule").split(":")[-1]

    return {
        "filename": os.path.basename(issue.get("component", "")),
        "cwe": cwe or "UNKNOWN",
        "line": issue.get("line", None)
    }


def main():
    parser = argparse.ArgumentParser(description="Exporta vulnerabilidades do SonarQube em JSON")
    parser.add_argument("-t", "--token", required=True, help="Token de acesso do SonarQube")
    parser.add_argument("-o", "--output", default="sonar_vulns.json", help="Arquivo JSON de saída")
    args = parser.parse_args()

    SONAR_URL = "http://localhost:9000"
    PROJECT_KEY = "gemini"

    print("🔍 Consultando vulnerabilidades no SonarQube...")

    raw_issues = fetch_all_issues(SONAR_URL, PROJECT_KEY, args.token)

    results = [normalize_issue(issue) for issue in raw_issues]

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"🎯 Exportação concluída!")
    print(f"📁 Vulnerabilidades salvas em: {args.output}")
    print(f"📌 Total de vulnerabilidades: {len(results)}")


if __name__ == "__main__":
    main()
