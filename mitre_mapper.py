"""
MITRE ATT&CK framework mapper for threat intelligence
"""
import json
import requests
from typing import List, Dict
from pathlib import Path
from loguru import logger
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import config


class MITREMapper:
    """Map threat data to MITRE ATT&CK framework"""
    
    def __init__(self, attack_data_path: str = None):
        # Normalize attack_data_path to a Path. If no path is configured, use a sensible default
        attack_data_path_str = attack_data_path or config.MITRE_DATA_PATH
        if not attack_data_path_str:
            # fallback to project data directory
            attack_data_path_str = str(Path(__file__).parent / 'data' / 'mitre_attack.json')
        self.attack_data_path = Path(attack_data_path_str)
        self.attack_framework = None
        self.techniques = []
        self.tactics = []
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.technique_vectors = None
        
        self._load_attack_data()
    
    def _load_attack_data(self):
        """Load MITRE ATT&CK data"""
        if self.attack_data_path.exists():
            with open(self.attack_data_path, 'r') as f:
                self.attack_framework = json.load(f)
                logger.info(f"Loaded MITRE ATT&CK data from {self.attack_data_path}")
        else:
            logger.warning(f"MITRE ATT&CK data not found at {self.attack_data_path}")
            logger.info("Attempting to download MITRE ATT&CK data...")
            self._download_attack_data()
        
        if self.attack_framework:
            self._parse_framework()
    
    def _download_attack_data(self):
        """Download MITRE ATT&CK data from official source"""
        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        
        try:
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            
            self.attack_framework = response.json()
            
            # Save to file
            config.DATA_DIR.mkdir(exist_ok=True, parents=True)
            with open(self.attack_data_path, 'w') as f:
                json.dump(self.attack_framework, f, indent=2)
            
            logger.info(f"Downloaded and saved MITRE ATT&CK data to {self.attack_data_path}")
        
        except Exception as e:
            logger.error(f"Failed to download MITRE ATT&CK data: {e}")
            # Create minimal fallback data
            self._create_fallback_data()
    
    def _create_fallback_data(self):
        """Create minimal fallback data structure"""
        self.attack_framework = {
            'objects': [
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--t1566',
                    'name': 'Phishing',
                    'description': 'Adversaries may send phishing messages to gain access to victim systems.',
                    'kill_chain_phases': [{'phase_name': 'initial-access'}],
                    'external_references': [{'external_id': 'T1566'}]
                },
                {
                    'type': 'attack-pattern',
                    'id': 'attack-pattern--t1059',
                    'name': 'Command and Scripting Interpreter',
                    'description': 'Adversaries may abuse command and script interpreters to execute commands.',
                    'kill_chain_phases': [{'phase_name': 'execution'}],
                    'external_references': [{'external_id': 'T1059'}]
                }
            ]
        }
        logger.info("Created fallback MITRE ATT&CK data")
    
    def _parse_framework(self):
        """Parse MITRE ATT&CK framework data"""
        self.techniques = []
        self.tactics = set()
        
        for obj in self.attack_framework.get('objects', []):
            if obj.get('type') == 'attack-pattern':
                technique = {
                    'id': self._get_external_id(obj),
                    'name': obj.get('name', ''),
                    'description': obj.get('description', ''),
                    'tactics': [phase.get('phase_name', '') 
                               for phase in obj.get('kill_chain_phases', [])],
                }
                self.techniques.append(technique)
                
                for tactic in technique['tactics']:
                    self.tactics.add(tactic)
        
        # Create vectors for similarity matching
        if self.techniques:
            descriptions = [t['description'] for t in self.techniques]
            self.technique_vectors = self.vectorizer.fit_transform(descriptions)
        
        logger.info(f"Parsed {len(self.techniques)} techniques and {len(self.tactics)} tactics")
    
    def _get_external_id(self, obj: Dict) -> str:
        """Extract external ID (e.g., T1566) from object"""
        for ref in obj.get('external_references', []):
            if 'external_id' in ref and ref['external_id'].startswith('T'):
                return ref['external_id']
        return obj.get('id', 'unknown')
    
    def map_text_to_techniques(self, text: str, threshold: float = None) -> List[Dict]:
        """Map text to MITRE ATT&CK techniques using similarity"""
        threshold = threshold or config.MITRE_SIMILARITY_THRESHOLD
        
        if not self.techniques or self.technique_vectors is None:
            logger.warning("MITRE ATT&CK data not loaded")
            return []
        
        # Vectorize input text
        text_vector = self.vectorizer.transform([text])
        
        # Calculate similarities
        similarities = cosine_similarity(text_vector, self.technique_vectors)[0]
        
        # Get top matches above threshold
        mappings = []
        for idx, similarity in enumerate(similarities):
            if similarity >= threshold:
                technique = self.techniques[idx]
                mappings.append({
                    'technique_id': technique['id'],
                    'technique_name': technique['name'],
                    'tactics': technique['tactics'],
                    'description': technique['description'][:200] + '...',
                    'confidence': float(similarity)
                })
        
        # Sort by confidence
        mappings.sort(key=lambda x: x['confidence'], reverse=True)
        
        logger.info(f"Mapped to {len(mappings)} MITRE ATT&CK techniques")
        return mappings
    
    def map_entities_to_techniques(self, entities: Dict) -> List[Dict]:
        """Map extracted entities to MITRE techniques"""
        mappings = []
        
        # Combine all entity text
        entity_text = ' '.join([
            ' '.join(entities.get('MALWARE', [])),
            ' '.join(entities.get('TTP', [])),
            ' '.join(entities.get('ACTOR', []))
        ])
        
        if entity_text.strip():
            mappings = self.map_text_to_techniques(entity_text)
        
        return mappings
    
    def get_technique_by_id(self, technique_id: str) -> Dict:
        """Get technique details by ID"""
        for technique in self.techniques:
            if technique['id'] == technique_id:
                return technique
        return None
    
    def get_techniques_by_tactic(self, tactic: str) -> List[Dict]:
        """Get all techniques for a specific tactic"""
        return [t for t in self.techniques if tactic in t['tactics']]
    
    def get_kill_chain_coverage(self, mapped_techniques: List[Dict]) -> Dict:
        """Analyze kill chain coverage from mapped techniques"""
        coverage = {tactic: [] for tactic in self.tactics}
        
        for mapping in mapped_techniques:
            for tactic in mapping['tactics']:
                if tactic in coverage:
                    coverage[tactic].append(mapping['technique_id'])
        
        # Calculate coverage percentage
        total_tactics = len(self.tactics)
        covered_tactics = sum(1 for techniques in coverage.values() if techniques)
        coverage_percent = (covered_tactics / total_tactics * 100) if total_tactics > 0 else 0
        
        return {
            'coverage': coverage,
            'covered_tactics': covered_tactics,
            'total_tactics': total_tactics,
            'coverage_percent': coverage_percent
        }
    
    def generate_attack_narrative(self, mapped_techniques: List[Dict]) -> str:
        """Generate a narrative description of the attack based on techniques"""
        if not mapped_techniques:
            return "No techniques identified."
        
        # Group by tactic
        tactics_dict = {}
        for mapping in mapped_techniques:
            for tactic in mapping['tactics']:
                if tactic not in tactics_dict:
                    tactics_dict[tactic] = []
                tactics_dict[tactic].append(mapping['technique_name'])
        
        # Generate narrative
        narrative_parts = []
        tactic_order = ['initial-access', 'execution', 'persistence', 'privilege-escalation',
                       'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
                       'collection', 'command-and-control', 'exfiltration', 'impact']
        
        for tactic in tactic_order:
            if tactic in tactics_dict:
                techniques = tactics_dict[tactic]
                narrative_parts.append(
                    f"{tactic.replace('-', ' ').title()}: {', '.join(techniques)}"
                )
        
        return '; '.join(narrative_parts)


if __name__ == "__main__":
    # Test MITRE mapper
    mapper = MITREMapper()
    
    sample_text = """
    The threat actor used spear phishing emails to gain initial access.
    They then executed PowerShell scripts to establish persistence.
    The malware communicated with a C2 server to exfiltrate data.
    """
    
    mappings = mapper.map_text_to_techniques(sample_text)
    
    print(f"\nMapped to {len(mappings)} techniques:\n")
    for mapping in mappings[:5]:
        print(f"  {mapping['technique_id']}: {mapping['technique_name']}")
        print(f"  Tactics: {', '.join(mapping['tactics'])}")
        print(f"  Confidence: {mapping['confidence']:.2f}\n")
    
    # Get kill chain coverage
    coverage = mapper.get_kill_chain_coverage(mappings)
    print(f"Kill Chain Coverage: {coverage['coverage_percent']:.1f}%")
    print(f"Covered {coverage['covered_tactics']}/{coverage['total_tactics']} tactics")