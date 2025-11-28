import json
import argparse
import os
from google import genai
from google.genai import types
import time


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

    # Inicializa client da Gemini
    client = genai.Client(api_key=args.api_key)

    # 🔥 AQUI O TRECHO QUE FALTAVA 🔥
    with open(args.list, "r", encoding="utf-8") as f:
        all_labels = json.load(f)

    # Organiza labels por arquivo (normalizando o caminho para apenas o nome do arquivo)
    labels_by_file = {}
    for item in all_labels:
        # Extrair apenas o nome do arquivo
        fname = os.path.basename(item["filename"])
        labels_by_file.setdefault(fname, []).append(item["cwe"])


    results = []

    for root, _, files in os.walk(args.source_code_dir):
        for file in files:
            if not file.endswith(".py"):
                continue

            file_path = os.path.join(root, file)
            rel_path = os.path.basename(file_path)

            if rel_path not in labels_by_file:
                continue

            with open(file_path, "r", encoding="utf-8") as f:
                code = f.read()

            labels2 = labels_by_file[rel_path]
            prompt = build_prompt(code, labels2)

            print(f"🔹 Chamando IA para: {rel_path} ...")
            start_time = time.time()

            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig( temperature=0.0 )
            )

            # Força 1 request por minuto
            elapsed = time.time() - start_time
            sleep_time = max(0, 30 - elapsed)
            print(f"⏳ Aguardando {sleep_time:.1f}s antes da próxima requisição...")
            time.sleep(sleep_time)


            print(response.text)
            raw_output = response.text.strip()

            try:
                ai_result = json.loads(raw_output)
            except json.JSONDecodeError:
                ai_result = raw_output

            results.append({
                "filename": rel_path,
                "ai_predictions": ai_result
            })

            print(f"✔️ Processado: {rel_path}")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print("\n🎯 Concluído!")
    print(f"📁 Saída: {args.output}")
    print(f"📌 Arquivos processados: {len(results)}")

if __name__ == "__main__":
    main()
