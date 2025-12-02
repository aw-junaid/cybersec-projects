#!/usr/bin/env python3
"""
Script to ingest IOCs from various feed formats
"""

import os
import sys
import json
import csv
import asyncio
import aiohttp
from datetime import datetime
from typing import List, Dict, Any
import argparse

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

async def ingest_csv(file_path: str, feed_name: str, api_url: str, api_key: str):
    """Ingest IOCs from CSV file"""
    iocs = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        for row in reader:
            # Map common CSV columns to IOC fields
            ioc_value = row.get('indicator') or row.get('value') or row.get('ioc')
            ioc_type = row.get('type') or row.get('ioc_type')
            
            if not ioc_value or not ioc_type:
                print(f"Skipping invalid row: {row}")
                continue
            
            ioc = {
                "value": ioc_value.strip(),
                "type": ioc_type.strip().lower(),
                "source": feed_name,
                "confidence": int(row['confidence']) if 'confidence' in row and row['confidence'] else None,
                "first_seen": parse_date(row.get('first_seen')),
                "last_seen": parse_date(row.get('last_seen')) or datetime.utcnow(),
                "tags": parse_tags(row.get('tags')),
                "description": row.get('description')
            }
            
            iocs.append(ioc)
    
    await send_to_api(iocs, feed_name, api_url, api_key)

async def ingest_json(file_path: str, feed_name: str, api_url: str, api_key: str):
    """Ingest IOCs from JSON file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    iocs = []
    
    # Handle different JSON structures
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict) and 'iocs' in data:
        items = data['iocs']
    elif isinstance(data, dict) and 'indicators' in data:
        items = data['indicators']
    else:
        items = [data]
    
    for item in items:
        if isinstance(item, dict):
            ioc_value = item.get('indicator') or item.get('value') or item.get('ioc')
            ioc_type = item.get('type') or item.get('ioc_type')
            
            if not ioc_value or not ioc_type:
                continue
            
            ioc = {
                "value": ioc_value.strip(),
                "type": ioc_type.strip().lower(),
                "source": feed_name,
                "confidence": item.get('confidence'),
                "first_seen": parse_date(item.get('first_seen')),
                "last_seen": parse_date(item.get('last_seen')) or datetime.utcnow(),
                "tags": parse_tags(item.get('tags')),
                "description": item.get('description')
            }
            iocs.append(ioc)
    
    await send_to_api(iocs, feed_name, api_url, api_key)

async def send_to_api(iocs: List[Dict], feed_name: str, api_url: str, api_key: str):
    """Send IOCs to API endpoint"""
    if not iocs:
        print("No valid IOCs found to ingest")
        return
    
    payload = {
        "iocs": iocs,
        "feed_name": feed_name,
        "feed_version": "1.0"
    }
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(f"{api_url}/ingest", json=payload, headers=headers) as response:
                if response.status == 202:
                    result = await response.json()
                    print(f"Successfully ingested {len(iocs)} IOCs")
                    print(f"Enrichment queued: {result.get('enrichment_queued', False)}")
                    print(f"IOC IDs: {result.get('ioc_ids', [])[:5]}...")  # Show first 5 IDs
                else:
                    error_text = await response.text()
                    print(f"API error {response.status}: {error_text}")
        except Exception as e:
            print(f"Request failed: {e}")

def parse_date(date_str: Any) -> datetime:
    """Parse date string to datetime object"""
    if not date_str:
        return datetime.utcnow()
    
    if isinstance(date_str, datetime):
        return date_str
    
    try:
        # Try ISO format
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except:
        try:
            # Try Unix timestamp
            return datetime.fromtimestamp(int(date_str))
        except:
            return datetime.utcnow()

def parse_tags(tags: Any) -> List[str]:
    """Parse tags from various formats"""
    if not tags:
        return []
    
    if isinstance(tags, list):
        return tags
    
    if isinstance(tags, str):
        return [tag.strip() for tag in tags.split(',')]
    
    return []

async def main():
    parser = argparse.ArgumentParser(description="Ingest IOCs from various formats")
    parser.add_argument("file", help="Input file path")
    parser.add_argument("--format", choices=['csv', 'json'], required=True, help="Input file format")
    parser.add_argument("--feed", required=True, help="Feed name")
    parser.add_argument("--api-url", default="http://localhost:8000", help="API base URL")
    parser.add_argument("--api-key", default="test-key", help="API key")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.file):
        print(f"Error: File {args.file} not found")
        sys.exit(1)
    
    try:
        if args.format == 'csv':
            await ingest_csv(args.file, args.feed, args.api_url, args.api_key)
        elif args.format == 'json':
            await ingest_json(args.file, args.feed, args.api_url, args.api_key)
    except Exception as e:
        print(f"Ingestion failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
