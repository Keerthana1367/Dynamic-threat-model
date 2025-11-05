# 🔐 Automotive Threat Modeling with LLM & MongoDB

This project demonstrates a complete workflow for **automotive cybersecurity threat modeling** using a combination of:

- 📚 A curated dataset of **50 attack surface prompts** (`ATT2.json`)
- 🤖 An **LLM (OpenAI GPT)** for generating structured **Mermaid.js attack trees**
- 🧠 An **interactive UI built with Gradio**
- 🛢️ **MongoDB** for storing threat trees and prompts
- 🌐 **Render** deployment for easy public access

---

## 🌟 Overview

This project automates the creation of **automotive attack trees** from natural-language threat descriptions.  
It leverages LLMs to expand high-level threats into detailed, hierarchical structures that follow cybersecurity standards — helping analysts quickly visualize and explore potential attack surfaces.

---

## 🧩 Project Structure

| File/Folder | Description |
|-------------|-------------|
| `ATT2.json` | 50 curated threat prompts related to automotive systems |
| `Threat_modelling_6thsem.ipynb` | Jupyter notebook for uploading prompts to MongoDB, testing LLM responses, and visualizing attack trees |
| `app.py` | Main Gradio web app (serves the interactive UI) |
| `requirements.txt` | Python dependencies for local or cloud deployment |
| `.env` | Contains API keys (excluded from GitHub for security) |
| `README.md` | This file — project documentation |

---

## 🌐 Live Demo

✅ Try the deployed app here:  
**🔗 [https://threat-model-3.onrender.com](https://threat-model-3.onrender.com)**  

*(If the demo is loading slowly, you can also run it locally — see instructions below.)*

---

## 🧪 Features

- 🔎 **Attack Tree Generation** — Enter or select a threat to automatically generate a hierarchical attack tree using GPT.
- 💾 **Database Integration** — Save and retrieve trees from MongoDB for future reference.
- 📊 **Data Export** — Export trees to CSV or JSON for documentation and reporting.
- ✏️ **Custom Threat Modeling** — Add your own prompts to expand the attack database.
- 🖼️ **Visualization** — View generated trees in a clean, interactive Gradio interface.

---

## ⚙️ Tech Stack

| Component | Technology |
|------------|-------------|
| Language | Python 3.10+ |
| Frontend | Gradio |
| Backend | OpenAI GPT (LLM) |
| Database | MongoDB Atlas |
| Deployment | Render |
| Format | Mermaid.js (attack tree representation) |

---

## 🚀 Quick Start (Run Locally)

1. **Clone the repository**
   ```bash
   git clone https://github.com/Keerthana1367/Dynamic-threat-model.git
   cd Dynamic-threat-model

