"""
Relationship extraction between threat entities
"""
import re
from typing import List, Dict, Tuple
from loguru import logger
import spacy


class RelationshipExtractor:
    """Extract relationships between threat entities"""
    
    def __init__(self):
        # Load spaCy for dependency parsing
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except Exception as e:
            logger.warning(f"Could not load spaCy model: {e}")
            logger.info("Run: python -m spacy download en_core_web_sm")
            self.nlp = None
        
        # Define relationship patterns
        self.patterns = {
            'uses': [
                r'(\w+)\s+uses?\s+(\w+)',
                r'(\w+)\s+leverages?\s+(\w+)',
                r'(\w+)\s+employs?\s+(\w+)'
            ],
            'exploits': [
                r'(\w+)\s+exploits?\s+(CVE-\d+-\d+)',
                r'(\w+)\s+targets?\s+(CVE-\d+-\d+)',
                r'(CVE-\d+-\d+)\s+exploited\s+by\s+(\w+)'
            ],
            'distributes': [
                r'(\w+)\s+distributes?\s+(\w+)',
                r'(\w+)\s+deploys?\s+(\w+)',
                r'(\w+)\s+delivers?\s+(\w+)'
            ],
            'communicates_with': [
                r'(\w+)\s+communicates?\s+with\s+(\d+\.\d+\.\d+\.\d+)',
                r'(\w+)\s+connects?\s+to\s+([\w\.-]+)',
                r'C2\s+server:?\s+([\w\.-]+)'
            ],
            'targets': [
                r'(\w+)\s+targets?\s+(\w+)',
                r'(\w+)\s+attacks?\s+(\w+)',
                r'campaign\s+against\s+(\w+)'
            ],
            'downloads': [
                r'(\w+)\s+downloads?\s+(\w+)',
                r'(\w+)\s+retrieves?\s+(\w+)',
                r'(\w+)\s+fetches?\s+(\w+)'
            ],
            'creates': [
                r'(\w+)\s+creates?\s+(\w+)',
                r'(\w+)\s+generates?\s+(\w+)',
                r'(\w+)\s+produces?\s+(\w+)'
            ]
        }
    
    def extract_relations(self, entities: Dict[str, List[str]], text: str) -> List[Dict]:
        """Extract relationships between entities using pattern matching"""
        relations = []
        text_lower = text.lower()
        
        # Pattern-based extraction
        for relation_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, text, re.IGNORECASE)
                for match in matches:
                    source = match.group(1)
                    target = match.group(2) if len(match.groups()) > 1 else None
                    
                    if target:
                        relations.append({
                            'source': source.strip(),
                            'relation': relation_type,
                            'target': target.strip(),
                            'confidence': 0.8
                        })
        
        # Dependency parsing based extraction (if spaCy available)
        if self.nlp:
            doc = self.nlp(text)
            dep_relations = self._extract_from_dependencies(doc, entities)
            relations.extend(dep_relations)
        
        # Remove duplicates
        unique_relations = []
        seen = set()
        
        for rel in relations:
            key = (rel['source'], rel['relation'], rel['target'])
            if key not in seen:
                seen.add(key)
                unique_relations.append(rel)
        
        logger.info(f"Extracted {len(unique_relations)} relationships")
        return unique_relations
    
    def _extract_from_dependencies(self, doc, entities: Dict) -> List[Dict]:
        """Extract relationships using dependency parsing"""
        relations = []
        
        for token in doc:
            # Look for verb relationships
            if token.pos_ == "VERB":
                # Find subject and object
                subjects = [child for child in token.children if child.dep_ in ("nsubj", "nsubjpass")]
                objects = [child for child in token.children if child.dep_ in ("dobj", "pobj")]
                
                for subj in subjects:
                    for obj in objects:
                        # Check if they are entities
                        if self._is_entity(subj.text, entities) and self._is_entity(obj.text, entities):
                            relations.append({
                                'source': subj.text,
                                'relation': token.lemma_,
                                'target': obj.text,
                                'confidence': 0.7
                            })
        
        return relations
    
    def _is_entity(self, text: str, entities: Dict) -> bool:
        """Check if text is a known entity"""
        text_lower = text.lower()
        for entity_type, entity_list in entities.items():
            if any(text_lower in e.lower() for e in entity_list):
                return True
        return False
    
    def extract_kill_chain_relations(self, entities: Dict, text: str) -> List[Dict]:
        """Extract cyber kill chain relationships"""
        kill_chain_stages = [
            'reconnaissance', 'weaponization', 'delivery', 'exploitation',
            'installation', 'command and control', 'actions on objectives'
        ]
        
        relations = []
        text_lower = text.lower()
        
        # Map entities to kill chain stages
        for stage in kill_chain_stages:
            if stage in text_lower:
                # Find nearby entities
                stage_idx = text_lower.index(stage)
                context = text[max(0, stage_idx-100):min(len(text), stage_idx+100)]
                
                # Extract entities in context
                for entity_type, entity_list in entities.items():
                    for entity in entity_list:
                        if entity.lower() in context.lower():
                            relations.append({
                                'entity': entity,
                                'kill_chain_stage': stage,
                                'entity_type': entity_type,
                                'confidence': 0.7
                            })
        
        return relations
    
    def build_attack_graph(self, relations: List[Dict]) -> Dict:
        """Build a graph representation of the attack"""
        graph = {
            'nodes': [],
            'edges': []
        }
        
        # Collect unique nodes
        nodes_set = set()
        for rel in relations:
            nodes_set.add(rel['source'])
            nodes_set.add(rel['target'])
        
        # Create nodes
        for node in nodes_set:
            graph['nodes'].append({
                'id': node,
                'label': node,
                'type': self._infer_node_type(node)
            })
        
        # Create edges
        for rel in relations:
            graph['edges'].append({
                'source': rel['source'],
                'target': rel['target'],
                'label': rel['relation'],
                'confidence': rel.get('confidence', 0.5)
            })
        
        return graph
    
    def _infer_node_type(self, node: str) -> str:
        """Infer node type from its text"""
        node_lower = node.lower()
        
        if re.match(r'cve-\d+-\d+', node_lower):
            return 'CVE'
        elif re.match(r'\d+\.\d+\.\d+\.\d+', node):
            return 'IP'
        elif re.match(r'[a-f0-9]{32,64}', node_lower):
            return 'Hash'
        elif 'apt' in node_lower or 'group' in node_lower:
            return 'ThreatActor'
        elif any(mal in node_lower for mal in ['malware', 'trojan', 'ransomware', 'backdoor']):
            return 'Malware'
        else:
            return 'Unknown'


if __name__ == "__main__":
    # Test relationship extraction
    extractor = RelationshipExtractor()
    
    sample_text = """
    APT29 uses Cobalt Strike to exploit CVE-2024-1234.
    The malware communicates with C2 server 192.168.1.100.
    The threat actor distributes ransomware via phishing emails.
    """
    
    sample_entities = {
        'ACTOR': ['APT29'],
        'MALWARE': ['Cobalt Strike', 'ransomware'],
        'CVE': ['CVE-2024-1234'],
        'IOC': ['192.168.1.100']
    }
    
    relations = extractor.extract_relations(sample_entities, sample_text)
    
    print("Extracted Relations:")
    for rel in relations:
        print(f"  {rel['source']} --[{rel['relation']}]--> {rel['target']}")
    
    graph = extractor.build_attack_graph(relations)
    print(f"\nAttack Graph: {len(graph['nodes'])} nodes, {len(graph['edges'])} edges")