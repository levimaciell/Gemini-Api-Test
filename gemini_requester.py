import json
import argparse
import os
from google import genai

def build_prompt(vul_code: str, labels2: list[str]) -> str:
    return (
        "Which of the following vulnerabilities from list of vulnerabilities exist "
        "in the python code which is delimited with triple backticks. also give the "
        "line of the vulnerability in the code.\n\n"
        f"Python code:\n'''\n{vul_code}\n'''\n\n"
        "List of vulnerabilities:\n"
        + ", ".join(labels2) +
        "\n\nFormat your response as a list of JSON objects with \"label\" and \"line of Code\" "
        "as the keys for each element. Only answer with JSON."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Executa IA como assistente de SAST em todos os arquivos Python de um diretório."
    )
    parser.add_argument(
        "-sc", "--source-code-dir", required=True,
        help="Diretório contendo os arquivos vulneráveis"
    )
    parser.add_argument(
        "-l", "--list", required=True,
        help="Arquivo .json contendo labels do SAST (ex: Bandit parser)"
    )
    parser.add_argument(
        "-ak", "--api-key", required=True,
        help="Chave da API do Google Gemini"
    )
    parser.add_argument(
        "-o", "--output", default="AiVulnAnalysis.json",
        help="Arquivo JSON de saída (default: AiVulnAnalysis.json)"
    )
    args = parser.parse_args()

    # Inicializa client da Gemini com o argumento
    client = genai.Client(api_key=args.api_key)


    results = []

    # Iterar sobre todos os arquivos Python do diretório
    for root, _, files in os.walk(args.source_code_dir):
        for file in files:
            if not file.endswith(".py"):
                continue

            file_path = os.path.join(root, file)

            # Construir caminho relativo igual ao do SAST output
            rel_path = os.path.relpath(file_path, start=args.source_code_dir)

            if rel_path not in labels_by_file:
                continue  # Nenhuma label do SAST para este arquivo → ignora

            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            labels2 = labels_by_file[rel_path]
            prompt = build_prompt(code, labels2)

            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                generation_config={"temperature": 0.0}
            )
            raw_output = response.text.strip()

            try:
                ai_result = json.loads(raw_output)
            except json.JSONDecodeError:
                ai_result = raw_output  # Falha → salva texto bruto para análise

            results.append({
                "filename": rel_path,
                "ai_predictions": ai_result
            })

            print(f"✔️ Processado: {rel_path}")

    # Salvar resultados no JSON final
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print("\n🎯 Concluído!")
    print(f"📁 Saída: {args.output}")
    print(f"📌 Arquivos processados: {len(results)}")


if __name__ == "__main__":
    main()
