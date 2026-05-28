#!/usr/bin/env python3
"""
Agent Tools for Security Cheatsheet Assistant
Custom tools that the agent can use to interact with cheatsheets
"""

import json
import logging
from typing import Any, Optional
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CheatsheetTools:
    """Custom tools for the cheatsheet agent"""

    def __init__(self, index_file: str = "agent/cheatsheet_index.json"):
        self.index_file = index_file
        self.index = self._load_index()

    def _load_index(self) -> list:
        """Load the cheatsheet index"""
        try:
            with open(self.index_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Index file not found: {self.index_file}")
            return []
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in {self.index_file}")
            return []

    def search_cheatsheets(self, query: str) -> dict:
        """
        Search for cheat sheets by topic or keyword
        
        Args:
            query: Search query string
            
        Returns:
            Dictionary with search results
        """
        if not self.index:
            return {"results": [], "error": "Index not loaded"}

        results = []
        query_lower = query.lower()

        for sheet in self.index:
            score = 0
            
            # Title match
            if query_lower in sheet.get('title', '').lower():
                score += 3
            
            # Description match
            if query_lower in sheet.get('description', '').lower():
                score += 2
            
            # Topic match
            for topic in sheet.get('topics', []):
                if query_lower in topic.lower():
                    score += 1

            if score > 0:
                results.append({
                    **sheet,
                    "relevance_score": score
                })

        # Sort by relevance
        results = sorted(results, key=lambda x: x['relevance_score'], reverse=True)
        
        return {
            "query": query,
            "count": len(results),
            "results": results[:5]
        }

    def get_cheatsheet_content(self, cheatsheet_id: str) -> dict:
        """
        Get full content of a specific cheat sheet
        
        Args:
            cheatsheet_id: The ID of the cheatsheet (filename without .md)
            
        Returns:
            Dictionary with cheatsheet content
        """
        for sheet in self.index:
            if sheet.get('id') == cheatsheet_id:
                try:
                    file_path = sheet.get('file')
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    return {
                        "id": cheatsheet_id,
                        "title": sheet.get('title'),
                        "content": content,
                        "file": file_path,
                        "success": True
                    }
                except FileNotFoundError:
                    return {
                        "id": cheatsheet_id,
                        "error": f"File not found: {sheet.get('file')}",
                        "success": False
                    }

        return {
            "id": cheatsheet_id,
            "error": f"Cheatsheet '{cheatsheet_id}' not found",
            "success": False
        }

    def list_all_cheatsheets(self) -> dict:
        """
        List all available cheat sheets
        
        Returns:
            Dictionary with list of all cheatsheets
        """
        if not self.index:
            return {"cheatsheets": [], "count": 0}

        cheatsheets = [
            {
                "id": s['id'],
                "title": s['title'],
                "description": s['description'],
                "topics": s['topics'],
                "word_count": s['word_count']
            }
            for s in self.index
        ]

        return {
            "count": len(cheatsheets),
            "cheatsheets": sorted(cheatsheets, key=lambda x: x['title'])
        }

    def get_security_recommendation(self, topic: str) -> dict:
        """
        Get security recommendations for a specific topic
        
        Args:
            topic: Security topic to get recommendations for
            
        Returns:
            Dictionary with recommendations from relevant cheatsheets
        """
        search_results = self.search_cheatsheets(topic)
        
        recommendations = {
            "topic": topic,
            "cheatsheets_found": search_results['count'],
            "recommendations": []
        }

        for result in search_results['results']:
            try:
                content = self.get_cheatsheet_content(result['id'])
                if content['success']:
                    # Extract first few paragraphs
                    text = content['content']
                    paragraphs = [p.strip() for p in text.split('\n\n') if p.strip() and not p.startswith('#')]
                    
                    recommendations['recommendations'].append({
                        "cheatsheet": result['title'],
                        "id": result['id'],
                        "excerpt": paragraphs[0][:500] if paragraphs else "No content available"
                    })
            except Exception as e:
                logger.error(f"Error getting recommendation for {result['id']}: {e}")

        return recommendations

    def get_related_topics(self, topic: str) -> dict:
        """
        Get related security topics
        
        Args:
            topic: Topic to find related topics for
            
        Returns:
            Dictionary with related topics
        """
        topic_lower = topic.lower()
        related = set()

        for sheet in self.index:
            if topic_lower in sheet.get('title', '').lower():
                related.update(sheet.get('topics', []))

        return {
            "query_topic": topic,
            "related_topics": sorted(list(related))[:10]
        }

    def get_tool_descriptions(self) -> dict:
        """Get descriptions of all available tools"""
        return {
            "tools": [
                {
                    "name": "search_cheatsheets",
                    "description": "Search for cheat sheets by topic or keyword",
                    "parameters": {"query": "str - Search query"}
                },
                {
                    "name": "get_cheatsheet_content",
                    "description": "Get full content of a specific cheat sheet",
                    "parameters": {"cheatsheet_id": "str - The ID of the cheatsheet"}
                },
                {
                    "name": "list_all_cheatsheets",
                    "description": "List all available cheat sheets",
                    "parameters": {}
                },
                {
                    "name": "get_security_recommendation",
                    "description": "Get security recommendations for a topic",
                    "parameters": {"topic": "str - Security topic"}
                },
                {
                    "name": "get_related_topics",
                    "description": "Get related security topics",
                    "parameters": {"topic": "str - Topic to find relations for"}
                }
            ]
        }


if __name__ == "__main__":
    tools = CheatsheetTools()
    
    # Test tools
    print("=== Testing CheatsheetTools ===\n")
    
    print("1. List all cheatsheets:")
    result = tools.list_all_cheatsheets()
    print(f"   Found {result['count']} cheatsheets\n")
    
    print("2. Search for 'authentication':")
    result = tools.search_cheatsheets("authentication")
    print(f"   Found {result['count']} results\n")
    
    print("3. Get recommendations for 'password':")
    result = tools.get_security_recommendation("password")
    print(f"   Found {result['cheatsheets_found']} relevant cheatsheets\n")
