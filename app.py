import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from nicegui import ui
from pymongo import MongoClient
import openai
import json

# 🔐 Setup API Keys and DB
openai.api_key = os.environ.get("OPENAI_API_KEY") or "your-openai-key"
mongo_uri = os.environ.get("MONGO_URI") or "your-mongo-uri"
client = MongoClient(mongo_uri)
db = client["threatmodeldb"]
collection = db["attacktrees"]
prompt_collection = db["prompts"]

# 🌐 FastAPI app
app = FastAPI()

# CORS (if needed)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# NiceGUI Web Interface
@ui.page("/")
async def main_page():
    ui.label("🔐 AI-Powered Automotive Threat Modeling Tool").classes("text-2xl font-bold")

    with ui.tabs().classes("w-full") as tabs:
        tab1 = ui.tab("📌 Tab 1: Label to Tree")
        tab2 = ui.tab("🆕 Tab 2: New Prompt")
        tab3 = ui.tab("💬 Tab 3: Free Input")
        tab4 = ui.tab("📚 Tab 4: Full Vectors")

    with ui.tab_panels(tabs, value=tab1).classes("w-full"):
        with ui.tab_panel(tab1):
            label = ui.input("Enter label or alias...")
            output1 = ui.textarea(label="Attack Tree").classes("w-full")
            ui.button("Generate", on_click=lambda: generate_from_label(label.value, output1))

        with ui.tab_panel(tab2):
            surface = ui.input("Attack Surface")
            goal = ui.input("Attack Goal")
            vector = ui.input("Attack Vector")
            technique = ui.input("Attack Technique")
            method = ui.input("Attack Method")
            output2 = ui.textarea(label="Generated Tree").classes("w-full")
            ui.button("Generate & Store", on_click=lambda: generate_new_prompt(surface.value, goal.value, vector.value, technique.value, method.value, output2))

        with ui.tab_panel(tab3):
            free_prompt = ui.textarea(label="Describe threat or label freely").classes("w-full")
            output3 = ui.textarea(label="Generated Tree").classes("w-full")
            ui.button("Interpret & Generate", on_click=lambda: interpret_free_prompt(free_prompt.value, output3))

        with ui.tab_panel(tab4):
            output4 = ui.textarea(label="All Vectors / Methods").classes("w-full")
            ui.button("Show All", on_click=lambda: fetch_full_library(output4))

# 🔧 Tab 1 Logic
def generate_from_label(label, output_box):
    prompt_doc = prompt_collection.find_one({"$or": [{"label": label}, {"aliases": label}]})
    if not prompt_doc:
        output_box.value = "❌ Label or alias not found."
        return
    prompt = prompt_doc["prompt"]
    result = call_openai(prompt)
    collection.insert_one({"label": label, "tree": result})
    output_box.value = result

# 🔧 Tab 2 Logic
def generate_new_prompt(surface, goal, vector, technique, method, output_box):
    prompt = f"""Attack Surface: {surface}
Goal: {goal}
Vector: {vector}
Technique: {technique}
Method: {method}
Generate a 3-level attack tree in Mermaid.js with AND/OR structure."""
    result = call_openai(prompt)
    label = f"{surface} - {goal}"
    prompt_collection.insert_one({"label": label, "prompt": prompt, "aliases": [surface.lower()]})
    collection.insert_one({"label": label, "tree": result})
    output_box.value = result

# 🔧 Tab 3 Logic
def interpret_free_prompt(user_input, output_box):
    doc = prompt_collection.find_one({"$or": [{"label": user_input}, {"aliases": user_input}]})
    prompt = doc["prompt"] if doc else f"Generate an attack tree for: {user_input}"
    result = call_openai(prompt)
    output_box.value = result

# 🔧 Tab 4 Logic
def fetch_full_library(output_box):
    docs = list(prompt_collection.find())
    formatted = "\n".join([f"{d['label']} → {d.get('prompt', '')[:100]}..." for d in docs])
    output_box.value = formatted or "📂 No records found."

# 🤖 OpenAI Call
def call_openai(prompt):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": "You are an automotive cybersecurity expert."},
                      {"role": "user", "content": prompt}],
            temperature=0.5,
            max_tokens=1000
        )
        return response["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Error: {e}"

# 🟢 Mount NiceGUI to FastAPI
ui.run_with(app)

# 🚀 Render Entry Point (PORT fix)
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    ui.run(host="0.0.0.0", port=port)

