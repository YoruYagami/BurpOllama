# BurpOllama: AI-Powered Pentesting Assistant for Burp Suite

**BurpOllama** is a lightweight Burp Suite extension that leverages local Ollama AI models to analyze HTTP requests and responses for potential security vulnerabilities. Enhance your penetration testing workflow with intelligent, automated vulnerability detection directly within Burp Suite.

## Features

- **AI-Powered Analysis:** Automatically detect vulnerabilities like SQL Injection, XSS, and more.
- **Chat Interface:** Interact with the AI assistant for detailed insights and recommendations.
- **Model Management:** Easily load, pull, and delete Ollama models.
- **Context Menu Integration:** Trigger analysis directly from Burp Suite's context menu.
- **Customizable Prompts:** Tailor AI responses with custom prompt templates.

## Installation

1. **Download the Extension:**
   - Clone the repository or download the latest `BurpOllama.py` from [Releases](https://github.com/yourusername/BurpOllamaPlusPlus/releases).

2. **Load into Burp Suite:**
   - Open Burp Suite and navigate to the **Extender** tab.
   - Go to the **Extensions** sub-tab and click **Add**.
   - Select **Python** as the extension type and browse to the downloaded `BurpOllama.py` file.
   - Click **Next** to load the extension.

## Configuration

1. **Set Ollama Endpoint:**
   - Navigate to the **Settings** tab within BurpOllama++.
   - Enter your local Ollama API endpoint (default: `http://localhost:11434/api/generate`).

2. **Manage Models:**
   - Use the **Load Models** button to fetch available Ollama models.
   - Select a model from the dropdown menu for analysis.

## Usage

1. **Manual Analysis:**
   - Right-click on any HTTP request or response within Burp Suite.
   - Navigate to **Send to BurpOllama > Send to Ollama** to initiate analysis.

2. **Chat Interface:**
   - Click on the **Chat** tab in BurpOllama++.
   - Interact with the AI assistant by typing your queries and receiving insights.

## License

This project is licensed under the [MIT License](./LICENSE).