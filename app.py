import os
import openai
from openai import OpenAI
import gradio as gr
from pymongo import MongoClient
from datetime import datetime
import re
import csv
import json
import pandas as pd
from collections import defaultdict, deque
from PyPDF2 import PdfReader

# ========================
# 🔐 Configurations (Environment Variables)
# ========================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MONGODB_URI = os.getenv("MONGODB_URI")

client_ai = OpenAI(api_key=OPENAI_API_KEY)
mongo_client = MongoClient(MONGODB_URI)
db = mongo_client["threat_db"]
attack_tree_collection = db["attack_trees"]
prompt_library = db["prompt_library"]

EXPORT_DIR = "csv_exports"
os.makedirs(EXPORT_DIR, exist_ok=True)

# ========================
# 🛠️ Utility Functions
# ========================
def parse_mermaid_to_named_edges(mermaid_code):
    node_labels = {}
    edges = []
    lines = mermaid_code.splitlines()
    for line in lines:
        node_match = re.findall(r'(\w+)\[(.+?)\]', line)
        for node_id, label in node_match:
            node_labels[node_id.strip()] = label.strip()
    edge_pattern = re.compile(r'(\w+)\s*-->\s*(\w+)')
    for line in lines:
        match = edge_pattern.search(line)
        if match:
            parent_id = match.group(1).strip()
            child_id = match.group(2).strip()
            parent_label = node_labels.get(parent_id, parent_id)
            child_label = node_labels.get(child_id, child_id)
            edges.append((parent_label, child_label))
    return edges

def build_ordered_paths(edges):
    tree = defaultdict(list)
    indegree = defaultdict(int)
    for parent, child in edges:
        tree[parent].append(child)
        indegree[child] += 1
    roots = set(tree.keys()) - set(indegree.keys())
    if not roots:
        return []
    root = list(roots)[0]
    paths = []
    queue = deque([(root, [root])])
    while queue:
        node, path = queue.popleft()
        if node not in tree:
            paths.append(path)
        else:
            for child in tree[node]:
                queue.append((child, path + [child]))
    return paths

def export_structured_csv(label, paths):
    safe_label = label[:30].replace(' ', '_').replace('/', '_')
    filename = f"{safe_label}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = os.path.join(EXPORT_DIR, filename)
    with open(filepath, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Surface Goal", "Attack Vector", "Technique", "Method", "Path"])
        for path in paths:
            row = path[:4] + [" > ".join(path)]
            while len(row) < 5:
                row.insert(len(row) - 1, "")
            writer.writerow(row)
    return filepath

def read_csv_as_dataframe(filepath):
    try:
        df = pd.read_csv(filepath)
        df.drop_duplicates(subset=["Path"], inplace=True)
        return df
    except Exception:
        return pd.DataFrame(columns=["Surface Goal", "Attack Vector", "Technique", "Method", "Path"])

# ========================
# Tab 1: Generate from label
# ========================
def generate_attack_tree_from_label(label_selected):
    if not label_selected:
        return "❌ Select a threat scenario."
    doc = prompt_library.find_one({"label": label_selected}) or prompt_library.find_one({"aliases": {"$in": [label_selected.lower()]}})
    if not doc or "prompt" not in doc:
        return f"❌ No prompt or alias found for '{label_selected}'"
    matched_prompt = doc["prompt"]
    label_to_save = doc["label"]
    try:
        system_message = {
            "role": "system",
            "content": "You are a cybersecurity expert. Return only the attack tree in Mermaid format using:\n```mermaid\ngraph TD\n...```"
        }
        response = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[system_message, {"role": "user", "content": matched_prompt}],
            temperature=0.3,
            max_tokens=1500
        )
        raw = response.choices[0].message.content.strip()
        match = re.search(r"```mermaid\s*(graph TD[\s\S]*?)```", raw)
        if not match:
            return "❌ Mermaid diagram not found or invalid format."
        mermaid_code = match.group(1).strip()
        attack_tree_collection.update_one(
            {"label": label_to_save},
            {"$set": {
                "prompt": matched_prompt,
                "mermaid_code": mermaid_code,
                "updated_at": datetime.utcnow()
            }},
            upsert=True
        )
        return f"```mermaid\n{mermaid_code}\n```"
    except Exception as e:
        return f"❌ Error: {str(e)}"

# ========================
# Tab 2: View Stored Trees
# ========================
def wrapper_load(label):
    if not label:
        return "❌ Select a saved attack tree.", pd.DataFrame(), None
    doc = attack_tree_collection.find_one({"label": label}) or prompt_library.find_one({"aliases": {"$in": [label.lower()]}})
    if doc and "label" in doc and "mermaid_code" not in doc:
        return generate_attack_tree_from_label(doc["label"]), pd.DataFrame(), None
    if not doc or "mermaid_code" not in doc:
        return "❌ No stored attack tree found.", pd.DataFrame(), None
    mermaid_code = doc["mermaid_code"]
    edges = parse_mermaid_to_named_edges(mermaid_code)
    paths = build_ordered_paths(edges)
    csv_path = export_structured_csv(doc["label"], paths)
    df = read_csv_as_dataframe(csv_path)
    return f"```mermaid\n{mermaid_code}\n```", df, csv_path

# ========================
# Tab 3: Free Prompt
# ========================
def generate_tree_from_free_prompt(prompt):
    if not prompt.strip():
        return "❌ Please enter a valid prompt"
    try:
        base_prompt = prompt
        system_msg = {
            "role": "system",
            "content": "You are a cybersecurity expert. Return the full updated attack tree in Mermaid format:\n```mermaid\ngraph TD\n...```"
        }
        response = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[system_msg, {"role": "user", "content": base_prompt}],
            temperature=0.3,
            max_tokens=1500
        )
        raw = response.choices[0].message.content.strip()
        match = re.search(r"```mermaid\s*(graph TD[\s\S]*?)```", raw)
        if not match:
            return "❌ Mermaid diagram not found or invalid format."
        mermaid_code = match.group(1).strip()
        return f"```mermaid\n{mermaid_code}\n```"
    except Exception as e:
        return f"❌ Error: {str(e)}"

# ========================
# Tab 4: Upload & Analyze File + Ask Questions
# ========================
def extract_text_from_pdf(file):
    try:
        reader = PdfReader(file)
        return "".join([page.extract_text() or "" for page in reader.pages])
    except:
        return ""

def read_file_content(file):
    ext = file.name.split('.')[-1].lower()
    if ext == "pdf":
        return extract_text_from_pdf(file)
    elif ext == "csv":
        df = pd.read_csv(file)
        return df.to_string(index=False)
    elif ext == "json":
        content = json.load(file)
        return json.dumps(content, indent=2)
    return ""

def process_uploaded_file(file):
    try:
        content = read_file_content(file)
        if not content:
            return "❌ Could not extract content."
        prompt = f"""Analyze the following content. If it includes prompts, generate attack trees using Mermaid.
If it includes Mermaid attack tree code, explain the tree, recommend improvements, and suggest mitigations.

Content:
{content}
"""
        system_msg = {
            "role": "system",
            "content": "You're a cybersecurity expert. If input is a prompt, return attack tree in Mermaid. If it's a tree, explain + mitigate."
        }
        response = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[system_msg, {"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=1600
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"❌ Error: {str(e)}"

def ask_question_about_file(file, question):
    try:
        content = read_file_content(file)
        if not content:
            return "❌ Could not extract file content."
        prompt = f"""Here is the content from a file:
{content[:3000]}

Now answer this question: {question}"""
        response = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity assistant helping users understand and analyze file content."},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"❌ Error: {str(e)}"

# ========================
# Dropdowns
# ========================
def get_all_labels():
    return sorted([doc["label"] for doc in prompt_library.find({}, {"label": 1})])

def get_stored_labels():
    return sorted(set([doc["label"] for doc in attack_tree_collection.find({"label": {"$exists": True}})]))

def refresh_dropdowns():
    return gr.update(choices=get_all_labels()), gr.update(choices=get_stored_labels())

# ========================
# Gradio UI
# ========================
with gr.Blocks() as demo:
    with gr.Tab("🫠 Generate Attack Tree"):
        label_dropdown = gr.Dropdown(choices=[], label="📌 Select or Type", interactive=True, allow_custom_value=True)
        generate_button = gr.Button("🚀 Generate Attack Tree")
        mermaid_display = gr.Markdown()
        generate_button.click(fn=generate_attack_tree_from_label, inputs=label_dropdown, outputs=mermaid_display)

    with gr.Tab("📂 Library"):
        saved_dropdown = gr.Dropdown(choices=[], label="📌 Select Stored Tree", interactive=True, allow_custom_value=True)
        mermaid_output = gr.Markdown()
        relation_table = gr.Dataframe(headers=["Surface Goal", "Attack Vector", "Technique", "Method", "Path"], datatype=["str"]*5, interactive=False)
        download_button = gr.File()
        regen_button = gr.Button("🔄 Regenerate Tree")
        saved_dropdown.change(fn=wrapper_load, inputs=saved_dropdown, outputs=[mermaid_output, relation_table, download_button])
        regen_button.click(fn=generate_attack_tree_from_label, inputs=saved_dropdown, outputs=mermaid_output)

    with gr.Tab("🗓️ Custom Prompt"):
        prompt_input = gr.Textbox(label="Enter Custom Prompt", lines=5)
        custom_mermaid_output = gr.Markdown()
        submit_button = gr.Button("Generate Tree")
        submit_button.click(fn=generate_tree_from_free_prompt, inputs=prompt_input, outputs=custom_mermaid_output)

    with gr.Tab("📄 Upload File"):
        file_input = gr.File(file_types=[".pdf", ".csv", ".json"], label="Upload Prompt or Tree File")
        file_output = gr.Markdown()
        question_box = gr.Textbox(label="Ask a question about the file")
        answer_box = gr.Markdown()
        process_button = gr.Button("📈 Process File")
        ask_button = gr.Button("🤔 Ask Question")
        process_button.click(fn=process_uploaded_file, inputs=file_input, outputs=file_output)
        ask_button.click(fn=ask_question_about_file, inputs=[file_input, question_box], outputs=answer_box)

    demo.load(fn=refresh_dropdowns, inputs=[], outputs=[label_dropdown, saved_dropdown])

# ========================
# 🚀 Launch App (for Render)
# ========================
if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=8080)
