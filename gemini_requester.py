import json
import argparse
import os
import time
from google import genai
from google.genai import types

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
        start_time = time.time()

        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.0)
            )
            raw = response.text.strip()
        except Exception as e:
            print(f"❗ Erro de requisição para {rel_path}: {e}")
            errors.append({"filename": rel_path, "error": str(e)})
            continue

        # esperar para limitar taxa se quiser
        elapsed = time.time() - start_time
        sleep_time = max(0, 30 - elapsed)
        if sleep_time > 0:
            print(f"⏳ Aguardando {sleep_time:.1f}s antes da próxima requisição...")
            time.sleep(sleep_time)

        try:
            ai_result = json.loads(raw)
        except json.JSONDecodeError:
            print(f"❗ Resposta inválida da IA para {rel_path}. Output bruto será salvo para análise.")
            errors.append({"filename": rel_path, "error": "Invalid JSON", "raw": raw})
            ai_result = raw  # ou None, dependendo do que quiser fazer

        results.append({
            "filename": rel_path,
            "ai_predictions": ai_result
        })

        print(f"✔️ Processado: {rel_path}")

    # salvar resultados
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"\n🎯 Concluído! {processed}/{total} arquivos processados com IA.")
    if errors:
        print(f"⚠️ Ocorreram {len(errors)} erros. Veja log em erro_ia_log.json")
        with open("erro_ia_log.json", "w", encoding="utf-8") as ef:
            json.dump(errors, ef, indent=2, ensure_ascii=False)
    else:
        print("✅ Nenhum erro detectado durante as requisições à IA.")

if __name__ == "__main__":
    main()
