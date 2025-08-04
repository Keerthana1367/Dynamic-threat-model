# app.py

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import gradio as gr
import uvicorn
import os
from datetime import datetime
from pymongo import MongoClient
from openai import OpenAI
import re
import csv
import pandas as pd
from collections import defaultdict, deque

# ========== Config ==========
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or "sk-proj-..."  # Replace with your secure key
MONGODB_URI = os.getenv("MONGO_URI") or "mongodb+srv://..."     # Replace with your secure URI

client_ai = OpenAI(api_key=OPENAI_API_KEY)
mongo_client = MongoClient(MONGODB_URI)
db = mongo_client["threat_db"]
attack_tree_collection = db["attack_trees"]
prompt_library = db["prompt_library"]
EXPORT_DIR = "csv_exports"
os.makedirs(EXPORT_DIR, exist_ok=True)

# ========== Utility ==========
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

def generate_attack_tree(label_or_prompt: str):
    doc = prompt_library.find_one({"label": label_or_prompt}) or \
          prompt_library.find_one({"aliases": {"$in": [label_or_prompt.lower()]}})

    if doc and "prompt" in doc:
        prompt = doc["prompt"]
        label = doc["label"]
    else:
        prompt = label_or_prompt
        label = "custom_" + datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    try:
        system_message = {
            "role": "system",
            "content": "You are a cybersecurity expert. Return only the attack tree in Mermaid format using:\n```mermaid\ngraph TD\n...```"
        }
        response = client_ai.chat.completions.create(
            model="gpt-4-turbo",
            messages=[system_message, {"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=1500
        )
        raw = response.choices[0].message.content.strip()
        match = re.search(r"```mermaid\s*(graph TD[\s\S]*?)```", raw)
        if not match:
            return None, "❌ Mermaid diagram not found."

        mermaid_code = match.group(1).strip()
        attack_tree_collection.update_one(
            {"label": label},
            {"$set": {"prompt": prompt, "mermaid_code": mermaid_code, "updated_at": datetime.utcnow()}},
            upsert=True
        )
        return mermaid_code, None
    except Exception as e:
        return None, str(e)

# ========== FastAPI App ==========
app = FastAPI(title="Threat Modeling API")

# Allow CORS if used from frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

@app.post("/generate-tree")
async def generate_tree_endpoint(request: Request):
    data = await request.json()
    label_or_prompt = data.get("input", "").strip()
    if not label_or_prompt:
        return JSONResponse(content={"error": "Prompt or label is required."}, status_code=400)

    mermaid_code, error = generate_attack_tree(label_or_prompt)
    if error:
        return JSONResponse(content={"error": error}, status_code=500)
    return {"label": label_or_prompt, "mermaid": mermaid_code}

# ========== Gradio UI ==========
def gradio_generate(label):
    code, err = generate_attack_tree(label)
    return f"```mermaid\n{code}\n```" if code else f"❌ {err}"

with gr.Blocks() as demo:
    with gr.Tab("🌐 Web Interface"):
        gr.Markdown("## 🔐 Threat Tree Generator")
        label_input = gr.Textbox(label="Prompt or Label")
        output = gr.Markdown()
        gen_btn = gr.Button("🚀 Generate")
        gen_btn.click(fn=gradio_generate, inputs=label_input, outputs=output)

@app.get("/")
def root():
    return {"message": "Threat Modeling API is running."}

@app.get("/gradio")
def launch_gradio():
    return demo.launch(share=True, inline=True, prevent_thread_lock=True)

# ========== Run ==========

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=7860, reload=True)
