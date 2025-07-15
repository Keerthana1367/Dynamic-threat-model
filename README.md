# Dynamic-threat-model
 AI-Powered Automotive Threat Modeling Tool

This project is an end-to-end **LLM-driven cybersecurity threat modeling tool** built for the **automotive domain**. It uses GPT-4 Turbo to dynamically generate attack trees based on vehicle functions, stores them in MongoDB, and allows users to interact with and extend threat models through a user-friendly Gradio UI.

🌐 **Live Demo:** [Visit the Render Website](https://your-render-url.com)

---

## 📌 Features

- 🧠 **LLM-Powered Threat Tree Generation**  
  Automatically generate attack trees from label-based or free-form prompts using OpenAI’s GPT-4 Turbo.

- 📊 **Structured Path Extraction**  
  Converts Mermaid.js attack trees into structured paths (vector → technique → method).

- 💾 **MongoDB Integration**  
  Stores prompt libraries, attack tree structures, and aliases for easy retrieval and update.

- ✍️ **Custom Prompt Extension**  
  Extends existing trees using natural language and intelligently updates MongoDB entries.

- 📤 **CSV Export**  
  Exports structured attack paths for documentation, analysis, or reporting.



