"""
Main entry point for the AI-Driven Threat Intelligence Platform
"""
import argparse
from loguru import logger
from pathlib import Path

from pipeline import ThreatIntelligencePlatform
import config


def setup_logging():
    """Configure logging"""
    logger.add(
        config.LOGS_DIR / "platform.log",
        rotation="10 MB",
        retention="7 days",
        level=config.LOG_LEVEL,
        format=config.LOG_FORMAT
    )


def collect_command(args):
    """Execute data collection"""
    logger.info(f"Starting data collection for query: '{args.query}'")
    
    platform = ThreatIntelligencePlatform()
    
    sources = args.sources.split(',') if args.sources else ['reddit', 'blog']
    
    results = platform.run_pipeline(
        query=args.query,
        sources=sources,
        limit=args.limit
    )
    
    print(f"\n{'='*60}")
    print(f"Collection Results for: '{results['query']}'")
    print(f"{'='*60}")
    print(f"✅ Collected: {results['collected_items']} items")
    print(f"✅ Processed: {results['processed_items']} items")
    print(f"\nAnalysis Summary:")
    print(f"  • Clusters: {results['analysis']['summary']['n_clusters']}")
    print(f"  • Anomalies: {results['analysis']['summary']['n_anomalies']}")
    print(f"  • Critical Threats: {results['analysis']['summary']['critical_threats']}")
    print(f"  • High Threats: {results['analysis']['summary']['high_threats']}")
    
    print(f"\nGraph Statistics:")
    for key, value in results['graph_stats'].items():
        print(f"  • {key}: {value}")
    
    platform.cleanup()


def analyze_command(args):
    """Execute threat analysis"""
    logger.info("Starting threat analysis")
    
    platform = ThreatIntelligencePlatform()
    
    # Read input text
    if args.file:
        with open(args.file, 'r') as f:
            text = f.read()
    else:
        text = args.text
    
    if not text:
        print("Error: No text provided. Use --text or --file")
        return
    
    result = platform.process_threat_data(text, "manual_input")
    
    print(f"\n{'='*60}")
    print(f"Threat Analysis Results")
    print(f"{'='*60}")
    
    print(f"\n📌 Extracted Entities:")
    for entity_type, entities in result['entities'].items():
        if entities:
            print(f"  • {entity_type}: {', '.join(entities[:5])}")
    
    print(f"\n🔗 Relationships:")
    for rel in result['relations'][:5]:
        print(f"  • {rel['source']} --[{rel['relation']}]--> {rel['target']}")
    
    print(f"\n🎯 MITRE ATT&CK Mappings:")
    for mapping in result['mitre_mappings'][:3]:
        print(f"  • {mapping['technique_id']}: {mapping['technique_name']}")
        print(f"    Tactics: {', '.join(mapping['tactics'])}")
        print(f"    Confidence: {mapping['confidence']:.2%}")
    
    print(f"\n⚠️  Threat Assessment:")
    sentiment = result['sentiment']
    print(f"  • Threat Level: {sentiment['threat_level']}")
    print(f"  • Urgency Score: {sentiment['urgency_score']:.1f}/10")
    print(f"  • Keywords: {', '.join(sentiment['keywords_found'][:5])}")
    
    platform.cleanup()


def dashboard_command(args):
    """Launch the dashboard"""
    import subprocess
    
    logger.info("Launching dashboard...")
    print(f"\n🚀 Starting Threat Intelligence Dashboard...")
    print(f"📊 Dashboard will open at: http://localhost:{args.port}")
    print(f"Press Ctrl+C to stop\n")
    
    try:
        subprocess.run([
            "streamlit", "run",
            "src/dashboard/app.py",
            "--server.port", str(args.port),
            "--server.headless", "true"
        ])
    except KeyboardInterrupt:
        print("\n\n✅ Dashboard stopped")


def stats_command(args):
    """Display platform statistics"""
    logger.info("Fetching platform statistics")
    
    platform = ThreatIntelligencePlatform()
    landscape = platform.get_threat_landscape()
    
    print(f"\n{'='*60}")
    print(f"Platform Statistics")
    print(f"{'='*60}")
    
    stats = landscape['statistics']
    print(f"\n📊 Database Statistics:")
    for key, value in stats.items():
        print(f"  • {key}: {value}")
    
    print(f"\n🔥 Recent Threats (Last 10):")
    for threat in landscape['recent_threats'][:10]:
        print(f"  • [{threat['type']}] {threat['name']}")
    
    platform.cleanup()


def search_command(args):
    """Search threats in database"""
    logger.info(f"Searching for: '{args.term}'")
    
    platform = ThreatIntelligencePlatform()
    results = platform.search_threats(args.term)
    
    print(f"\n{'='*60}")
    print(f"Search Results for: '{args.term}'")
    print(f"{'='*60}")
    
    if results:
        print(f"\nFound {len(results)} results:\n")
        for result in results[:20]:
            print(f"  • [{result['type']}] {result['name']}")
    else:
        print("\n❌ No results found")
    
    platform.cleanup()


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="AI-Driven Threat Intelligence Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Collect and analyze threats
  python main.py collect --query "ransomware" --sources "reddit,blog" --limit 50
  
  # Analyze specific threat text
  python main.py analyze --text "APT29 exploits CVE-2024-1234"
  
  # Analyze threat from file
  python main.py analyze --file threat_report.txt
  
  # Launch dashboard
  python main.py dashboard
  
  # View statistics
  python main.py stats
  
  # Search database
  python main.py search --term "APT29"
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Collect command
    collect_parser = subparsers.add_parser('collect', help='Collect and process threat data')
    collect_parser.add_argument('--query', '-q', required=True, help='Search query')
    collect_parser.add_argument('--sources', '-s', help='Comma-separated sources (reddit,blog,twitter)')
    collect_parser.add_argument('--limit', '-l', type=int, default=50, help='Number of items to collect')
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze threat text')
    analyze_parser.add_argument('--text', '-t', help='Threat text to analyze')
    analyze_parser.add_argument('--file', '-f', help='File containing threat text')
    
    # Dashboard command
    dashboard_parser = subparsers.add_parser('dashboard', help='Launch web dashboard')
    dashboard_parser.add_argument('--port', '-p', type=int, default=8501, help='Dashboard port')
    
    # Stats command
    subparsers.add_parser('stats', help='Display platform statistics')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search threats in database')
    search_parser.add_argument('--term', '-t', required=True, help='Search term')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging()
    
    # Execute command
    if args.command == 'collect':
        collect_command(args)
    elif args.command == 'analyze':
        analyze_command(args)
    elif args.command == 'dashboard':
        dashboard_command(args)
    elif args.command == 'stats':
        stats_command(args)
    elif args.command == 'search':
        search_command(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║   AI-Driven Threat Intelligence Platform                 ║
    ║   CS 760 - Artificial Intelligence                       ║
    ║   University of Alabama at Birmingham                    ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    main()