# app.py
import os
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from gradio.routes import mount_gradio_app
import gradio as gr
from openai import OpenAI
from pymongo import MongoClient
from datetime import datetime
from collections import defaultdict, deque
from PyPDF2 import PdfReader
import pandas as pd
import re
import csv
import json
from dotenv import load_dotenv

# ==================================
# 🔐 Load .env
# ==================================
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
MONGODB_URI = os.getenv("MONGODB_URI")

# ==================================
# 🧠 Clients
# ==================================
client_ai = OpenAI(api_key=OPENAI_API_KEY)
mongo_client = MongoClient(MONGODB_URI) if MONGODB_URI else None
db = mongo_client["threat_db"] if mongo_client else None
attack_tree_collection = db["attack_trees"] if db else None
prompt_library = db["prompt_library"] if db else None
webhook_events_collection = db["webhook_events"] if db else None

# ==================================
# 📁 Directories
# ==================================
EXPORT_DIR = "csv_exports"
os.makedirs(EXPORT_DIR, exist_ok=True)

# ==================================
# 🚀 FastAPI Setup
# ==================================
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/webhook")
async def webhook_receiver(request: Request):
    try:
        payload = await request.json()
    except Exception:
        payload = (await request.body()).decode("utf-8", "ignore")

    if webhook_events_collection:
        webhook_events_collection.insert_one({
            "data": payload,
            "received_at": datetime.utcnow()
        })

    return {"status": "Webhook received", "data": payload}

# ==================================
# 🧰 Utility Functions
# ==================================
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
            parent = node_labels.get(match.group(1), match.group(1))
            child = node_labels.get(match.group(2), match.group(2))
            edges.append((parent, child))
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
    safe_label = (label or "export")[:30].replace(' ', '').replace('/', '')
    filename = f"{safe_label}{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.csv"
    filepath = os.path.join(EXPORT_DIR, filename)
    with open(filepath, "w", newline='', encoding='utf-8') as f:
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
        if "Path" in df.columns:
            df.drop_duplicates(subset=["Path"], inplace=True)
        return df
    except:
        return pd.DataFrame()

# ==================================
# 🔄 Gradio Tab Functions
# ==================================

def generate_attack_tree_from_label(label):
    if not label:
        return "❌ Please select a label"
    doc = prompt_library.find_one({"label": label}) or prompt_library.find_one({"aliases": {"$in": [label.lower()]}})
    if not doc or "prompt" not in doc:
        return f"❌ No prompt for label '{label}'"
    prompt = doc["prompt"]
    try:
        response = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Use Mermaid format:\ngraph TD"},
                {"role": "user", "content": prompt}
            ]
        )
        raw = response.choices[0].message.content.strip()
        match = re.search(r"mermaid\s*(graph TD[\s\S]*?)", raw, re.IGNORECASE)
        if not match:
            return "❌ Mermaid format not found."
        mermaid_code = match.group(1).strip()
        attack_tree_collection.update_one(
            {"label": label},
            {"$set": {"prompt": prompt, "mermaid_code": mermaid_code, "updated_at": datetime.utcnow()}},
            upsert=True
        )
        return f"mermaid\n{mermaid_code}"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def wrapper_load(label):
    if not label:
        return "❌ Select label", pd.DataFrame(), None
    doc = attack_tree_collection.find_one({"label": label})
    if not doc or "mermaid_code" not in doc:
        return "❌ Mermaid code not found", pd.DataFrame(), None
    mermaid = doc["mermaid_code"]
    edges = parse_mermaid_to_named_edges(mermaid)
    paths = build_ordered_paths(edges)
    csv_path = export_structured_csv(label, paths)
    df = read_csv_as_dataframe(csv_path)
    return f"mermaid\n{mermaid}", df, csv_path

def generate_tree_from_free_prompt(prompt):
    if not prompt:
        return "❌ Empty prompt"
    try:
        response = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Use Mermaid format:\ngraph TD"},
                {"role": "user", "content": prompt}
            ]
        )
        raw = response.choices[0].message.content.strip()
        match = re.search(r"mermaid\s*(graph TD[\s\S]*?)", raw, re.IGNORECASE)
        if not match:
            return "❌ Mermaid format not found."
        return f"mermaid\n{match.group(1).strip()}"
    except Exception as e:
        return f"❌ Error: {str(e)}"

def process_uploaded_file(file):
    try:
        text = extract_text_from_pdf(file)
        prompt = f"""Analyze the following content. If it includes prompts, generate attack trees using Mermaid.
Content:\n{text}"""
        response = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[
                {"role": "system", "content": "You're a cybersecurity expert."},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"❌ Error: {str(e)}"

def load_webhook_events():
    if not webhook_events_collection:
        return pd.DataFrame(columns=["Received At", "Data"])
    events = list(webhook_events_collection.find().sort("received_at", -1).limit(20))
    data = []
    for event in events:
        ts = event.get("received_at")
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ""
        payload = json.dumps(event.get("data"), indent=2) if isinstance(event.get("data"), dict) else str(event.get("data"))
        data.append([ts_str, payload])
    return pd.DataFrame(data, columns=["Received At", "Data"])

def get_all_labels():
    return sorted([doc["label"] for doc in prompt_library.find({}, {"label": 1}) if "label" in doc])

def get_stored_labels():
    return sorted(set([doc["label"] for doc in attack_tree_collection.find({"label": {"$exists": True}}, {"label": 1})]))

def refresh_dropdowns():
    return gr.update(choices=get_all_labels()), gr.update(choices=get_stored_labels()), load_webhook_events()

# ==================================
# 🌟 Gradio UI
# ==================================
with gr.Blocks() as demo:
    with gr.Tab("🫠 Generate Attack Tree"):
        label_dropdown = gr.Dropdown(label="Threat Scenario", choices=[], interactive=True)
        generate_btn = gr.Button("Generate")
        mermaid_out = gr.Markdown()
        generate_btn.click(fn=generate_attack_tree_from_label, inputs=label_dropdown, outputs=mermaid_out)

    with gr.Tab("📂 Library"):
        saved_dropdown = gr.Dropdown(label="Stored Attack Tree", choices=[], interactive=True)
        mermaid_view = gr.Markdown()
        df_view = gr.Dataframe()
        file_out = gr.File()
        saved_dropdown.change(fn=wrapper_load, inputs=saved_dropdown, outputs=[mermaid_view, df_view, file_out])

    with gr.Tab("🧠 Custom Prompt"):
        prompt_box = gr.Textbox(label="Prompt", lines=6)
        submit_btn = gr.Button("Submit")
        custom_output = gr.Markdown()
        submit_btn.click(fn=generate_tree_from_free_prompt, inputs=prompt_box, outputs=custom_output)

    with gr.Tab("📄 Upload File"):
        file_input = gr.File(label="Upload PDF")
        file_btn = gr.Button("Analyze")
        file_result = gr.Markdown()
        file_btn.click(fn=process_uploaded_file, inputs=file_input, outputs=file_result)

    with gr.Tab("📡 Webhook Events"):
        webhook_table = gr.Dataframe()
    
    demo.load(fn=refresh_dropdowns, inputs=[], outputs=[label_dropdown, saved_dropdown, webhook_table])

# Mount Gradio UI at root
app = mount_gradio_app(app, demo, path="/")
