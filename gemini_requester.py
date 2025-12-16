import json
import argparse
import os
import time
from google import genai
from google.genai import types

MAX_RETRIES = 3
RETRY_DELAY = 5

def build_prompt(vul_code: str, labels2: list[str]) -> str:
    return (
        "Which of the following vulnerabilities from list of vulnerabilities exist "
        "in the python code which is delimited with triple backticks. also give the "
        "number of the line of the vulnerability in the code.\n\n"
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

    client = genai.Client(api_key=args.api_key)

    with open(args.list, "r", encoding="utf-8") as f:
        all_labels = json.load(f)

    labels_by_file = {}
    for item in all_labels:
        fname = os.path.basename(item["filename"])
        labels_by_file.setdefault(fname, []).append(item["cwe"])

    # Contar quantos arquivos serão processados
    files_to_process = []
    for root, _, files in os.walk(args.source_code_dir):
        for file in files:
            if file.endswith(".py") and os.path.basename(file) in labels_by_file:
                files_to_process.append(os.path.join(root, file))

    for file in files_to_process:
        print(os.path.basename(file))

    total = len(files_to_process)
    print(f"🔎 Encontrados {total} arquivos para processar pela IA.")

    results = []
    errors = []

    processed = 0
    for file_path in files_to_process:
        processed += 1
        rel_path = os.path.basename(file_path)

        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()

        labels2 = labels_by_file.get(rel_path, [])
        prompt = build_prompt(code, labels2)

        print(f"\n[{processed}/{total}] 🔹 Chamando IA para: {rel_path} ...")

        success = False
        last_error = None
        raw = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                print(f"   🔁 Tentativa {attempt}/{MAX_RETRIES}")

                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                    config=types.GenerateContentConfig(temperature=0.0)
                )

                raw = response.text.strip()

                if raw.startswith("```"):
                    raw = raw.replace("```json", "").replace("```", "").strip()

                ai_result = json.loads(raw)
                success = True
                break

            except json.JSONDecodeError:
                last_error = "Invalid JSON"
                print("   ⚠️ JSON inválido retornado pela IA")

            except Exception as e:
                last_error = str(e)
                print(f"   ⚠️ Erro de requisição: {last_error}")

            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

        # =============================
        # Falha definitiva
        # =============================
        if not success:
            print(f"❌ Falha definitiva em {rel_path}\n")
            errors.append({
                "filename": rel_path,
                "error": last_error,
                "raw": raw
            })
            continue

        # =============================
        # Sucesso
        # =============================
        results.append({
            "filename": rel_path,
            "ai_predictions": ai_result
        })

        print(f"✔️ Processado com sucesso: {rel_path}\n")

    # =============================
    # Salva resultados
    # =============================
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print(f"\n🎯 Concluído! {processed}/{total} arquivos processados.")

    if errors:
        print(f"⚠️ Ocorreram {len(errors)} erros. Veja: erro_ia_log.json")
        with open("erro_ia_log.json", "w", encoding="utf-8") as ef:
            json.dump(errors, ef, indent=2, ensure_ascii=False)
    else:
        print("✅ Nenhum erro detectado durante as requisições à IA.")


if __name__ == "__main__":
    main()