#!/usr/bin/env python3
"""
Security Cheatsheet Agent
Powered by Google Gemini and AgentKit
"""

import os
import json
import logging
from typing import Optional, List, Dict, Any
from dotenv import load_dotenv
import google.generativeai as genai
from agent_tools import CheatsheetTools

# Load environment variables
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecurityCheatsheetAgent:
    """Agent powered by CheatSheetSeries and Gemini"""

    def __init__(self, model: str = "gemini-2.0-flash"):
        """
        Initialize the Security Cheatsheet Agent
        
        Args:
            model: Gemini model to use
        """
        # Setup Gemini API
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY environment variable not set")
        
        genai.configure(api_key=api_key)
        self.model_name = model
        self.model = genai.GenerativeModel(model)
        
        # Initialize tools
        self.tools = CheatsheetTools()
        
        # Agent configuration
        self.name = "🛡️ Security Cheatsheet Assistant"
        self.description = "An AI agent that helps developers find and understand security best practices"
        
        # System prompt
        self.system_prompt = """You are a security expert assistant powered by the OWASP Cheat Sheet Series.

Your capabilities:
- Search and retrieve security cheat sheets
- Provide detailed security guidance
- Recommend best practices for various security topics
- Answer questions about application security
- Help developers understand security vulnerabilities and mitigations

Guidelines:
1. Always cite the cheat sheets you're referencing
2. Provide practical, actionable advice
3. Explain security concepts clearly
4. Suggest multiple approaches when available
5. Warn about common security mistakes
6. Link to relevant cheat sheets when applicable

Available tools:
- search_cheatsheets(query): Search for relevant cheat sheets
- get_cheatsheet_content(id): Get full content of a specific cheat sheet
- list_all_cheatsheets(): List all available resources
- get_security_recommendation(topic): Get recommendations for a specific topic
- get_related_topics(topic): Find related security topics

Always try to use these tools to provide the most accurate and relevant information."""

        logger.info(f"✓ Agent initialized with model: {model}")

    def _format_tool_response(self, tool_name: str, tool_result: Dict) -> str:
        """Format tool response for inclusion in prompt"""
        return json.dumps(tool_result, indent=2, ensure_ascii=False)

    def _process_tool_calls(self, user_query: str) -> Dict[str, Any]:
        """
        Process user query and determine which tools to use
        
        Args:
            user_query: The user's question/request
            
        Returns:
            Dictionary with tool results
        """
        results = {"query": user_query, "tools_used": [], "data": {}}
        
        query_lower = user_query.lower()
        
        # Determine which tools to use based on query
        if "list" in query_lower or "all" in query_lower:
            result = self.tools.list_all_cheatsheets()
            results["tools_used"].append("list_all_cheatsheets")
            results["data"]["cheatsheets"] = result
        
        if "search" in query_lower or any(keyword in query_lower for keyword in 
                                          ["what", "how", "find", "about", "tell me"]):
            result = self.tools.search_cheatsheets(user_query)
            results["tools_used"].append("search_cheatsheets")
            results["data"]["search_results"] = result
        
        if "recommend" in query_lower or "best practice" in query_lower:
            # Extract topic from query
            result = self.tools.get_security_recommendation(user_query)
            results["tools_used"].append("get_security_recommendation")
            results["data"]["recommendations"] = result
        
        # Always do a general search if nothing else matched
        if not results["tools_used"]:
            result = self.tools.search_cheatsheets(user_query)
            results["tools_used"].append("search_cheatsheets")
            results["data"]["search_results"] = result
        
        return results

    def run(self, user_query: str) -> str:
        """
        Process user query and generate response
        
        Args:
            user_query: The user's question/request
            
        Returns:
            Agent response
        """
        logger.info(f"Processing query: {user_query}")
        
        # Get tool results
        tool_results = self._process_tool_calls(user_query)
        
        # Format context from tools
        context = f"""Tool Results:
{self._format_tool_response('tools', tool_results['data'])}

User Query: {user_query}

Use the above information to provide a comprehensive, helpful response."""
        
        try:
            # Generate response using Gemini
            response = self.model.generate_content(
                f"{self.system_prompt}\n\n{context}",
                generation_config=genai.types.GenerationConfig(
                    max_output_tokens=2048,
                    temperature=0.7,
                )
            )
            
            answer = response.text
            logger.info("✓ Response generated successfully")
            
            return answer
            
        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return f"Error processing query: {str(e)}"

    def run_interactive(self) -> None:
        """Run agent in interactive mode"""
        print(f"\n{self.name}")
        print(f"{self.description}")
        print("\n" + "="*60)
        print("Type 'exit' or 'quit' to end the conversation")
        print("Type 'help' for available commands")
        print("="*60 + "\n")
        
        while True:
            try:
                user_input = input("\n📝 You: ").strip()
                
                if not user_input:
                    continue
                
                if user_input.lower() in ['exit', 'quit']:
                    print("\n👋 Goodbye!")
                    break
                
                if user_input.lower() == 'help':
                    print(self._show_help())
                    continue
                
                print("\n🤖 Agent:", end=" ")
                response = self.run(user_input)
                print(response)
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                logger.error(f"Error: {e}")
                print(f"Error: {e}")

    def _show_help(self) -> str:
        """Show help information"""
        return """
Available Commands:
- Type any security-related question
- "list cheatsheets" - Show all available cheatsheets
- "search [topic]" - Search for specific topic
- "recommend [topic]" - Get recommendations for a topic
- "help" - Show this help message
- "exit" or "quit" - Exit the agent

Example Queries:
- What are the best practices for authentication?
- How do I prevent SQL injection?
- Show me cheatsheets on OWASP top 10
- What are the secure password storage recommendations?
"""

    def batch_process(self, queries: List[str]) -> List[Dict[str, str]]:
        """
        Process multiple queries
        
        Args:
            queries: List of queries to process
            
        Returns:
            List of responses
        """
        results = []
        for query in queries:
            response = self.run(query)
            results.append({"query": query, "response": response})
        return results


def main():
    """Main entry point"""
    try:
        # Initialize agent
        agent = SecurityCheatsheetAgent()
        
        # Example queries
        example_queries = [
            "What are the best practices for authentication?",
            "How do I prevent SQL injection?",
            "List all available security cheatsheets",
        ]
        
        print(f"\n{agent.name}")
        print(f"{agent.description}\n")
        print("="*60)
        print("Running example queries...\n")
        
        results = agent.batch_process(example_queries)
        
        for result in results:
            print(f"📝 Query: {result['query']}")
            print(f"🤖 Response: {result['response'][:500]}...")
            print("\n" + "-"*60 + "\n")

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "interactive":
        agent = SecurityCheatsheetAgent()
        agent.run_interactive()
    else:
        main()
