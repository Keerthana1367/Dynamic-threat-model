import gradio as gr
from pymongo import MongoClient
import os
import openai
import pandas as pd
from datetime import datetime

# ========================
# 🔐 CONFIGURATION
# ========================
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") or "your-openai-key-here"
MONGO_URI = os.getenv("MONGO_URI") or "mongodb+srv://<username>:<password>@cluster.mongodb.net/"

client = MongoClient(MONGO_URI)
db = client["ThreatModelDB"]
prompts_col = db["prompts"]
trees_col = db["attack_trees"]

openai.api_key = OPENAI_API_KEY


# ========================
# 🔁 LLM CALLER
# ========================
def query_llm(prompt):
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.3
    )
    return response['choices'][0]['message']['content']


# ========================
# 📌 TAB 1: Generate From Label or Alias
# ========================
def generate_from_label(label):
    doc = prompts_col.find_one({"$or": [{"label": label}, {"aliases": label}]})
    if not doc:
        return f"❌ No matching label or alias found for '{label}'"
    tree = query_llm(doc['prompt'])
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    trees_col.insert_one({"label": label, "tree": tree, "timestamp": timestamp})
    return tree


# ========================
# 🔁 TAB 2: Retrieve Existing Tree
# ========================
def get_tree_from_mongo(label):
    doc = trees_col.find_one({"label": label}, sort=[("timestamp", -1)])
    if not doc:
        return f"❌ No tree found for label '{label}'"
    return doc['tree']


# ========================
# 🆕 TAB 3: Custom Prompt Input (Not Stored)
# ========================
def generate_tree_from_free_prompt(prompt):
    return query_llm(prompt)


# ========================
# 📄 TAB 4: Upload CSV and Generate Summary
# ========================
def process_csv(file):
    df = pd.read_csv(file.name)
    summary = f"🟢 CSV contains {len(df)} rows and {len(df.columns)} columns:\n\n"
    summary += "\n".join(f"- {col}" for col in df.columns)
    return summary


# ========================
# 🚀 GRADIO UI
# ========================
with gr.Blocks() as demo:
    gr.Markdown("# 🚗 AI Threat Modeling System (Gradio GUI)")

    with gr.Tabs():
        # -----------------------
        with gr.Tab("📌 Tab 1: From Label/Alias"):
            label_input = gr.Textbox(label="Enter Label or Alias")
            output_1 = gr.Textbox(label="Generated Attack Tree")
            btn_1 = gr.Button("Generate")
            btn_1.click(fn=generate_from_label, inputs=label_input, outputs=output_1)

        # -----------------------
        with gr.Tab("📁 Tab 2: Retrieve Stored Tree"):
            label_retrieve = gr.Textbox(label="Enter Label")
            output_2 = gr.Textbox(label="Stored Attack Tree")
            btn_2 = gr.Button("Retrieve")
            btn_2.click(fn=get_tree_from_mongo, inputs=label_retrieve, outputs=output_2)

        # -----------------------
        with gr.Tab("✍️ Tab 3: Free-form Prompt"):
            prompt_input = gr.Textbox(lines=5, label="Enter Custom Prompt")
            output_3 = gr.Textbox(label="Generated Tree")
            btn_3 = gr.Button("Generate from Prompt")
            btn_3.click(fn=generate_tree_from_free_prompt, inputs=prompt_input, outputs=output_3)

        # -----------------------
        with gr.Tab("📊 Tab 4: Upload CSV"):
            file_input = gr.File(label="Upload CSV File", file_types=[".csv"])
            output_4 = gr.Textbox(label="CSV Summary")
            btn_4 = gr.Button("Analyze CSV")
            btn_4.click(fn=process_csv, inputs=file_input, outputs=output_4)

# For deployment compatibility
demo.launch(server_name="0.0.0.0", server_port=int(os.getenv("PORT", 7860)))
