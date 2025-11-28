"""
Main threat intelligence pipeline - integrates all components
"""
import sys
from pathlib import Path
from typing import List, Dict
from loguru import logger

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from data_collector import ThreatDataCollector
from text_preprocessor import TextPreprocessor
from ner_model import ThreatNERModel
from relationship_extractor import RelationshipExtractor
from graph_db import ThreatGraphDB
from mitre_mapper import MITREMapper
from threat_analyzer import ThreatAnalyzer
import config


class ThreatIntelligencePlatform:
    """Main AI-driven threat intelligence platform"""
    
    def __init__(self, load_ner_model: bool = False):
        logger.info("Initializing Threat Intelligence Platform...")
        
        # Initialize components
        self.collector = ThreatDataCollector()
        self.preprocessor = TextPreprocessor()
        self.relation_extractor = RelationshipExtractor()
        self.graph_db = ThreatGraphDB()
        self.mitre_mapper = MITREMapper()
        self.threat_analyzer = ThreatAnalyzer()
        
        # NER model (optional - requires training first)
        self.ner_model = None
        if load_ner_model:
            try:
                self.ner_model = ThreatNERModel()
                model_path = config.MODELS_DIR / "threat-ner"
                if model_path.exists():
                    self.ner_model.load_model(str(model_path))
                    logger.info("NER model loaded successfully")
            except Exception as e:
                logger.warning(f"Could not load NER model: {e}")
        
        logger.info("Platform initialized successfully")
    
    def collect_data(self, query: str, sources: List[str] = None, 
                    limit: int = 100) -> List[Dict]:
        """Collect threat data from various sources"""
        logger.info(f"Collecting data for query: '{query}'")
        
        raw_data = self.collector.collect_all(query, sources, limit)
        logger.info(f"Collected {len(raw_data)} items")
        
        return raw_data
    
    def process_threat_data(self, raw_text: str, source: str = "unknown") -> Dict:
        """Process a single threat data item through the pipeline"""
        logger.info(f"Processing threat data from {source}")
        
        result = {
            'source': source,
            'raw_text': raw_text,
            'entities': {},
            'iocs': {},
            'relations': [],
            'mitre_mappings': [],
            'sentiment': {},
            'graph_created': False
        }
        
        try:
            # Step 1: Preprocess text
            cleaned_text = self.preprocessor.clean_text(raw_text)
            result['cleaned_text'] = cleaned_text
            
            # Step 2: Extract IOCs using regex
            iocs = self.preprocessor.extract_iocs(raw_text)
            cves = self.preprocessor.extract_cves(raw_text)
            result['iocs'] = iocs
            result['cves'] = cves
            
            # Step 3: Extract entities using NER (if model available)
            if self.ner_model:
                entities = self.ner_model.extract_entities(cleaned_text)
                result['entities'] = entities
            else:
                # Use regex-based extraction as fallback
                result['entities'] = {
                    'IOC': iocs.get('ips', []) + iocs.get('domains', []),
                    'CVE': cves,
                    'MALWARE': [],
                    'ACTOR': [],
                    'TTP': []
                }
            
            # Step 4: Extract relationships
            relations = self.relation_extractor.extract_relations(
                result['entities'], cleaned_text
            )
            result['relations'] = relations
            
            # Step 5: Map to MITRE ATT&CK
            mitre_mappings = self.mitre_mapper.map_text_to_techniques(cleaned_text)
            result['mitre_mappings'] = mitre_mappings[:5]  # Top 5
            
            # Step 6: Sentiment/urgency analysis
            sentiment = self.threat_analyzer.sentiment_analyzer.analyze_urgency(cleaned_text)
            result['sentiment'] = sentiment
            
            # Step 7: Store in graph database
            self._store_in_graph(result)
            result['graph_created'] = True
            
            logger.info("Threat data processed successfully")
            
        except Exception as e:
            logger.error(f"Error processing threat data: {e}")
            result['error'] = str(e)
        
        return result
    
    def _store_in_graph(self, processed_data: Dict):
        """Store processed data in Neo4j graph database"""
        try:
            entities = processed_data.get('entities', {})
            relations = processed_data.get('relations', [])
            
            # Create entity nodes
            for entity_type, entity_list in entities.items():
                for entity in entity_list:
                    if entity_type == 'ACTOR':
                        self.graph_db.create_threat_actor(entity)
                    elif entity_type == 'MALWARE':
                        self.graph_db.create_malware(entity)
                    elif entity_type == 'CVE':
                        self.graph_db.create_cve(entity)
                    elif entity_type == 'IOC':
                        self.graph_db.create_ioc(entity, 'unknown')
            
            # Create IOC nodes
            iocs = processed_data.get('iocs', {})
            for ip in iocs.get('ips', []):
                self.graph_db.create_ioc(ip, 'ip')
            for domain in iocs.get('domains', []):
                self.graph_db.create_ioc(domain, 'domain')
            for hash_val in iocs.get('hashes', []):
                self.graph_db.create_ioc(hash_val, 'hash')
            
            # Create relationships
            for relation in relations:
                self.graph_db.create_relationship(
                    relation['source'],
                    relation['target'],
                    relation['relation'].upper().replace(' ', '_'),
                    {'confidence': relation.get('confidence', 0.5)}
                )
            
            # Create MITRE technique nodes and relationships
            for mapping in processed_data.get('mitre_mappings', [])[:3]:
                self.graph_db.create_ttp(
                    mapping['technique_id'],
                    {
                        'name': mapping['technique_name'],
                        'tactics': ','.join(mapping['tactics'])
                    }
                )
            
            logger.info("Data stored in graph database")
            
        except Exception as e:
            logger.error(f"Error storing in graph database: {e}")
    
    def process_batch(self, raw_data_list: List[Dict]) -> List[Dict]:
        """Process multiple threat data items"""
        results = []
        
        for i, item in enumerate(raw_data_list):
            logger.info(f"Processing item {i+1}/{len(raw_data_list)}")
            
            text = item.get('text', item.get('title', ''))
            source = item.get('source', 'unknown')
            
            if text:
                result = self.process_threat_data(text, source)
                result['original_item'] = item
                results.append(result)
        
        return results
    
    def analyze_threats(self, processed_data: List[Dict]) -> Dict:
        """Analyze processed threats for patterns"""
        # Extract texts for batch analysis
        threat_items = []
        for item in processed_data:
            threat_items.append({
                'text': item.get('cleaned_text', item.get('raw_text', '')),
                'source': item.get('source', 'unknown')
            })
        
        # Run batch analysis
        analysis = self.threat_analyzer.analyze_batch(threat_items)
        
        return analysis
    
    def run_pipeline(self, query: str, sources: List[str] = None, 
                    limit: int = 50) -> Dict:
        """Run the complete pipeline end-to-end"""
        logger.info(f"Starting pipeline for query: '{query}'")
        
        # Step 1: Collect data
        raw_data = self.collect_data(query, sources, limit)
        
        if not raw_data:
            logger.warning("No data collected")
            return {'status': 'no_data', 'results': []}
        
        # Step 2: Process data
        processed_data = self.process_batch(raw_data)
        
        # Step 3: Analyze threats
        analysis = self.analyze_threats(processed_data)
        
        # Step 4: Get graph statistics
        graph_stats = self.graph_db.get_threat_statistics()
        
        logger.info("Pipeline completed successfully")
        
        return {
            'status': 'success',
            'query': query,
            'collected_items': len(raw_data),
            'processed_items': len(processed_data),
            'analysis': analysis,
            'graph_stats': graph_stats,
            'results': processed_data[:10]  # Return top 10 for preview
        }
    
    def get_threat_landscape(self) -> Dict:
        """Get current threat landscape from graph database"""
        return {
            'statistics': self.graph_db.get_threat_statistics(),
            'recent_threats': self.graph_db.get_recent_threats(20),
            'graph_data': self.graph_db.get_graph_for_visualization(50)
        }
    
    def search_threats(self, search_term: str) -> List[Dict]:
        """Search for threats in the database"""
        return self.graph_db.search_threats(search_term, limit=20)
    
    def cleanup(self):
        """Cleanup resources"""
        if self.graph_db:
            self.graph_db.close()
        logger.info("Platform cleanup complete")


def main():
    """Example usage of the platform"""
    # Initialize platform
    platform = ThreatIntelligencePlatform()
    
    # Example 1: Run full pipeline
    results = platform.run_pipeline(
        query="ransomware",
        sources=['reddit', 'blog'],
        limit=10
    )
    
    print(f"\n{'='*60}")
    print(f"Pipeline Results for query: '{results['query']}'")
    print(f"{'='*60}")
    print(f"Collected: {results['collected_items']} items")
    print(f"Processed: {results['processed_items']} items")
    print(f"\nAnalysis Summary:")
    print(f"  Clusters: {results['analysis']['summary']['n_clusters']}")
    print(f"  Anomalies: {results['analysis']['summary']['n_anomalies']}")
    print(f"  Critical: {results['analysis']['summary']['critical_threats']}")
    print(f"  High: {results['analysis']['summary']['high_threats']}")
    print(f"\nGraph Statistics:")
    for key, value in results['graph_stats'].items():
        print(f"  {key}: {value}")
    
    # Example 2: Get threat landscape
    landscape = platform.get_threat_landscape()
    print(f"\nThreat Landscape:")
    print(f"  Total nodes: {sum(landscape['statistics'].values())}")
    print(f"  Recent threats: {len(landscape['recent_threats'])}")
    
    # Cleanup
    platform.cleanup()


if __name__ == "__main__":
    main()