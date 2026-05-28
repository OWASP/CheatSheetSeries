# 🛡️ Security Cheatsheet Agent

An intelligent AI agent powered by **Google Gemini** and the **OWASP Cheat Sheet Series** that helps developers find and understand security best practices.

## Features

- 🤖 **Intelligent Agent**: Powered by Google Gemini 2.0 Flash LLM
- 📚 **Cheatsheet Index**: Automatically indexes all OWASP cheatsheets
- 🔍 **Smart Search**: Semantic search for security topics
- 💬 **Interactive Chat**: Real-time conversation mode
- 🌐 **REST API**: Full-featured API for integration
- 📊 **Batch Processing**: Process multiple queries at once

## Quick Start

### 1. Install Dependencies
```bash
cd agent
pip install -r requirements.txt
```

### 2. Configure API Key
```bash
cp .env.example .env
# Edit .env and add your GOOGLE_API_KEY from https://aistudio.google.com/app/apikeys
```

### 3. Index Cheatsheets
```bash
python main.py index
```

### 4. Run the Agent
```bash
# Interactive mode
python main.py chat

# Demo mode
python main.py demo

# Batch mode
python main.py batch "What is authentication?" "How to prevent XSS?"
```

## API Usage

Start the API server:
```bash
pip install flask flask-cors
python main.py api --port 5000
```

Example API requests:
```bash
# Query the agent
curl -X POST http://localhost:5000/api/v1/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What are the best practices for authentication?"}'

# Search cheatsheets
curl -X POST http://localhost:5000/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query": "authentication"}'

# List all cheatsheets
curl http://localhost:5000/api/v1/cheatsheets

# Get recommendations
curl -X POST http://localhost:5000/api/v1/recommendations \
  -H "Content-Type: application/json" \
  -d '{"topic": "password security"}'
```

## Project Structure

```
agent/
├── .env.example              # Environment template
├── requirements.txt          # Python dependencies
├── README.md                 # This file
├── indexer.py               # Cheatsheet indexing
├── agent_tools.py           # Agent tools
├── agent.py                 # Main agent logic
├── api_server.py            # Flask API server
└── main.py                  # CLI entry point
```

## Documentation

See [QUICKSTART.md](QUICKSTART.md) for a quick 5-minute setup guide.

## Requirements

- Python 3.8+
- Google API Key (from https://aistudio.google.com/app/apikeys)

## License

Uses resources from OWASP Cheat Sheet Series (CC BY-SA 4.0)

---

**Made with ❤️ for security-conscious developers**
