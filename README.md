# 🔐 Automotive Threat Modeling with LLM & MongoDB

This project demonstrates a complete workflow for **automotive cybersecurity threat modeling** using a combination of:

- 📚 A curated dataset of **50 attack surface prompts** (`ATT2.json`)
- 🤖 An LLM (OpenAI GPT) for generating structured **Mermaid.js attack trees**
- 🧠 Interactive UI built with **Gradio**
- 🛢️ Threat trees and prompts stored in **MongoDB**
- 🌐 Deployed website via **Render**

---

## Project Structure

| File/Folder | Description |
|-------------|-------------|
| `ATT2.json` | Contains 50 curated threat prompts related to vehicle attack surfaces |
| `Threat_modelling_6thsem.ipynb` | Jupyter notebook for uploading prompts to MongoDB, testing LLM responses, and visualizing trees |
| `requirements.txt` | All required Python packages for local or cloud deployment |
| `.env` | Contains your API keys (not uploaded to GitHub for security) |
| `README.md` | This file — documentation for the repo |

---

## 🌐 Live Website

✅ You can try the deployed app here:  
**🔗https://threat-model-3.onrender.com**

---

## 🧪 Features

- 🔎 **Tab 1**: Select a threat label and generate the full attack tree using LLM.
- 📂 **Tab 2**: View saved attack trees from MongoDB and export structured CSV.
- 🧠 **Tab 3**: Enter free-form prompts to extend or create new threat models.


