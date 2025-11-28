#!/usr/bin/env python3
"""Run the full threat intelligence collection + MITRE mapping pipeline with one command.

Usage: python run.py --query ransomware --sources twitter,reddit --limit 50 --output outputs/results.json
"""
import argparse
import json
from pathlib import Path
from loguru import logger

import config
from data_collector import ThreatDataCollector
from mitre_mapper import MITREMapper


def main():
    parser = argparse.ArgumentParser(description='Run threat collection and MITRE mapping')
    parser.add_argument('--query', '-q', default='ransomware', help='Search query')
    parser.add_argument('--sources', '-s', default='twitter,reddit,blog,stix,darkweb', help='Comma-separated sources')
    parser.add_argument('--limit', '-n', type=int, default=50, help='Per-source limit')
    parser.add_argument('--output', '-o', default=str(config.DATA_DIR / 'outputs' / 'results.json'), help='Output JSON file')
    parser.add_argument('--threshold', '-t', type=float, default=getattr(config, 'MITRE_SIMILARITY_THRESHOLD', 0.7), help='MITRE similarity threshold (0-1)')

    args = parser.parse_args()

    # Ensure output directory exists
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    sources = [s.strip() for s in args.sources.split(',') if s.strip()]

    logger.info(f"Starting collection for query='{args.query}' sources={sources} limit={args.limit}")

    collector = ThreatDataCollector()
    mapper = MITREMapper()

    # Run collection
    results = collector.collect_all(args.query, sources=sources, limit=args.limit)

    # Process and map
    processed = []
    for item in results:
        text = item.get('text') or item.get('title') or ''
        mappings = mapper.map_text_to_techniques(text, threshold=args.threshold) if text else []
        item['mitre_mappings'] = mappings
        processed.append(item)

    # Save
    with open(out_path, 'w') as f:
        json.dump({'query': args.query, 'sources': sources, 'results': processed}, f, indent=2)

    logger.info(f"Saved {len(processed)} collected items to {out_path}")

    # Summary
    counts_by_source = {}
    total_mapped = 0
    for r in processed:
        src = r.get('source', 'unknown')
        counts_by_source[src] = counts_by_source.get(src, 0) + 1
        if r.get('mitre_mappings'):
            total_mapped += 1

    logger.info(f"Counts by source: {counts_by_source}")
    logger.info(f"Items with MITRE mappings: {total_mapped}/{len(processed)}")


if __name__ == '__main__':
    main()
