"""
Neo4j graph database for threat intelligence
"""
from neo4j import GraphDatabase
from typing import List, Dict, Optional
from loguru import logger
import config


class ThreatGraphDB:
    """Neo4j graph database manager for threat intelligence"""
    
    def __init__(self, uri: str = None, user: str = None, password: str = None):
        self.uri = uri or config.NEO4J_URI
        self.user = user or config.NEO4J_USER
        self.password = password or config.NEO4J_PASSWORD
        
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password)
            )
            logger.info(f"Connected to Neo4j at {self.uri}")
            self._create_indexes()
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
    
    def close(self):
        """Close database connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def _create_indexes(self):
        """Create indexes for better performance"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS FOR (n:ThreatActor) ON (n.name)",
            "CREATE INDEX IF NOT EXISTS FOR (n:Malware) ON (n.name)",
            "CREATE INDEX IF NOT EXISTS FOR (n:CVE) ON (n.id)",
            "CREATE INDEX IF NOT EXISTS FOR (n:IOC) ON (n.value)",
            "CREATE INDEX IF NOT EXISTS FOR (n:TTP) ON (n.technique_id)"
        ]
        
        with self.driver.session() as session:
            for index in indexes:
                try:
                    session.run(index)
                except Exception as e:
                    logger.warning(f"Index creation warning: {e}")
    
    def create_threat_actor(self, name: str, properties: Dict = None) -> Dict:
        """Create a threat actor node"""
        with self.driver.session() as session:
            result = session.execute_write(
                self._create_node, "ThreatActor", name, properties or {}
            )
            logger.info(f"Created ThreatActor: {name}")
            return result
    
    def create_malware(self, name: str, properties: Dict = None) -> Dict:
        """Create a malware node"""
        with self.driver.session() as session:
            result = session.execute_write(
                self._create_node, "Malware", name, properties or {}
            )
            logger.info(f"Created Malware: {name}")
            return result
    
    def create_cve(self, cve_id: str, properties: Dict = None) -> Dict:
        """Create a CVE node"""
        with self.driver.session() as session:
            properties = properties or {}
            properties['id'] = cve_id
            result = session.execute_write(
                self._create_node, "CVE", cve_id, properties
            )
            logger.info(f"Created CVE: {cve_id}")
            return result
    
    def create_ioc(self, ioc_value: str, ioc_type: str, properties: Dict = None) -> Dict:
        """Create an IOC node"""
        with self.driver.session() as session:
            properties = properties or {}
            properties['value'] = ioc_value
            properties['type'] = ioc_type
            result = session.execute_write(
                self._create_node, "IOC", ioc_value, properties
            )
            logger.info(f"Created IOC: {ioc_value} ({ioc_type})")
            return result
    
    def create_ttp(self, technique_id: str, properties: Dict = None) -> Dict:
        """Create a TTP (Tactics, Techniques, Procedures) node"""
        with self.driver.session() as session:
            properties = properties or {}
            properties['technique_id'] = technique_id
            result = session.execute_write(
                self._create_node, "TTP", technique_id, properties
            )
            logger.info(f"Created TTP: {technique_id}")
            return result
    
    @staticmethod
    def _create_node(tx, label: str, name: str, properties: Dict):
        """Transaction function to create a node"""
        query = f"""
        MERGE (n:{label} {{name: $name}})
        SET n += $properties
        SET n.updated_at = datetime()
        RETURN n
        """
        result = tx.run(query, name=name, properties=properties)
        return result.single()[0]
    
    def create_relationship(self, source_name: str, target_name: str, 
                          rel_type: str, properties: Dict = None) -> Dict:
        """Create a relationship between two nodes"""
        with self.driver.session() as session:
            result = session.execute_write(
                self._create_rel, source_name, target_name, rel_type, properties or {}
            )
            logger.info(f"Created relationship: {source_name} --[{rel_type}]--> {target_name}")
            return result
    
    @staticmethod
    def _create_rel(tx, source_name: str, target_name: str, 
                   rel_type: str, properties: Dict):
        """Transaction function to create a relationship"""
        query = f"""
        MATCH (a {{name: $source_name}})
        MATCH (b {{name: $target_name}})
        MERGE (a)-[r:{rel_type}]->(b)
        SET r += $properties
        SET r.created_at = datetime()
        RETURN r
        """
        result = tx.run(
            query,
            source_name=source_name,
            target_name=target_name,
            properties=properties
        )
        return result.single()[0] if result.peek() else None
    
    def find_node(self, name: str, label: str = None) -> Optional[Dict]:
        """Find a node by name"""
        with self.driver.session() as session:
            if label:
                query = f"MATCH (n:{label} {{name: $name}}) RETURN n"
            else:
                query = "MATCH (n {name: $name}) RETURN n"
            
            result = session.run(query, name=name)
            record = result.single()
            return dict(record[0]) if record else None
    
    def get_threat_actor_relationships(self, actor_name: str) -> List[Dict]:
        """Get all relationships for a threat actor"""
        with self.driver.session() as session:
            query = """
            MATCH (a:ThreatActor {name: $actor_name})-[r]->(n)
            RETURN type(r) as relationship, n.name as target, labels(n)[0] as target_type
            """
            result = session.run(query, actor_name=actor_name)
            return [dict(record) for record in result]
    
    def get_attack_path(self, start_node: str, end_node: str, max_depth: int = 5) -> List[Dict]:
        """Find attack paths between two nodes"""
        with self.driver.session() as session:
            query = """
            MATCH path = shortestPath(
                (start {name: $start_node})-[*..%d]->(end {name: $end_node})
            )
            RETURN [node in nodes(path) | node.name] as nodes,
                   [rel in relationships(path) | type(rel)] as relationships
            """ % max_depth
            
            result = session.run(query, start_node=start_node, end_node=end_node)
            return [dict(record) for record in result]
    
    def get_connected_threats(self, node_name: str, depth: int = 2) -> Dict:
        """Get all threats connected to a node"""
        with self.driver.session() as session:
            query = """
            MATCH (start {name: $node_name})-[r*1..%d]-(connected)
            RETURN DISTINCT connected.name as name, 
                   labels(connected)[0] as type,
                   length(r) as distance
            ORDER BY distance
            LIMIT 100
            """ % depth
            
            result = session.run(query, node_name=node_name)
            return [dict(record) for record in result]
    
    def get_threat_statistics(self) -> Dict:
        """Get overall threat statistics"""
        with self.driver.session() as session:
            query = """
            MATCH (n)
            RETURN labels(n)[0] as type, count(n) as count
            ORDER BY count DESC
            """
            result = session.run(query)
            stats = {record['type']: record['count'] for record in result}
            
            # Get relationship counts
            query = "MATCH ()-[r]->() RETURN count(r) as total_relationships"
            result = session.run(query)
            stats['total_relationships'] = result.single()['total_relationships']
            
            return stats
    
    def get_recent_threats(self, limit: int = 10) -> List[Dict]:
        """Get recently added threats"""
        with self.driver.session() as session:
            query = """
            MATCH (n)
            WHERE n.updated_at IS NOT NULL
            RETURN n.name as name, 
                   labels(n)[0] as type,
                   n.updated_at as timestamp
            ORDER BY n.updated_at DESC
            LIMIT $limit
            """
            result = session.run(query, limit=limit)
            return [dict(record) for record in result]
    
    def search_threats(self, search_term: str, limit: int = 20) -> List[Dict]:
        """Search for threats by name"""
        with self.driver.session() as session:
            query = """
            MATCH (n)
            WHERE toLower(n.name) CONTAINS toLower($search_term)
            RETURN n.name as name, 
                   labels(n)[0] as type,
                   n
            LIMIT $limit
            """
            result = session.run(query, search_term=search_term, limit=limit)
            return [dict(record) for record in result]
    
    def get_graph_for_visualization(self, limit: int = 100) -> Dict:
        """Get graph data for visualization"""
        with self.driver.session() as session:
            query = """
            MATCH (n)-[r]->(m)
            RETURN n.name as source, 
                   type(r) as relationship,
                   m.name as target,
                   labels(n)[0] as source_type,
                   labels(m)[0] as target_type
            LIMIT $limit
            """
            result = session.run(query, limit=limit)
            
            nodes = {}
            edges = []
            
            for record in result:
                source = record['source']
                target = record['target']
                
                if source not in nodes:
                    nodes[source] = {
                        'id': source,
                        'label': source,
                        'type': record['source_type']
                    }
                
                if target not in nodes:
                    nodes[target] = {
                        'id': target,
                        'label': target,
                        'type': record['target_type']
                    }
                
                edges.append({
                    'source': source,
                    'target': target,
                    'label': record['relationship']
                })
            
            return {
                'nodes': list(nodes.values()),
                'edges': edges
            }
    
    def clear_database(self):
        """Clear all nodes and relationships (use with caution!)"""
        with self.driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")
            logger.warning("Database cleared!")


if __name__ == "__main__":
    # Test the database
    db = ThreatGraphDB()
    
    # Create sample data
    db.create_threat_actor("APT29", {"country": "Russia", "active": True})
    db.create_malware("Cobalt Strike", {"type": "RAT"})
    db.create_cve("CVE-2024-1234", {"severity": "critical"})
    
    # Create relationships
    db.create_relationship("APT29", "Cobalt Strike", "USES")
    db.create_relationship("Cobalt Strike", "CVE-2024-1234", "EXPLOITS")
    
    # Query
    stats = db.get_threat_statistics()
    print(f"Threat Statistics: {stats}")
    
    # Close connection
    db.close()