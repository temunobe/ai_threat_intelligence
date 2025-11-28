#!/usr/bin/env python3
"""
Safe environment checker for required credentials.
Prints which keys are missing (does NOT print secret values).
"""
import os
from pathlib import Path

required = {
    'twitter_v2': ['TWITTER_BEARER_TOKEN'],
    'twitter_v1': ['TWITTER_API_KEY', 'TWITTER_API_SECRET', 'TWITTER_ACCESS_TOKEN', 'TWITTER_ACCESS_SECRET'],
    'reddit': ['REDDIT_CLIENT_ID', 'REDDIT_CLIENT_SECRET', 'REDDIT_USER_AGENT'],
    'neo4j': ['NEO4J_URI', 'NEO4J_USER', 'NEO4J_PASSWORD']
}

def check_group(name, keys):
    missing = [k for k in keys if not os.getenv(k)]
    if missing:
        print(f"[{name}] missing: {', '.join(missing)}")
    else:
        print(f"[{name}] OK")

def main():
    print(f"Env check in: {Path.cwd()}")
    for name, keys in required.items():
        check_group(name, keys)

if __name__ == '__main__':
    main()
